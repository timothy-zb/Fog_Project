% Define fog nodes
numNodes = 6; % Define total number of nodes
fogNodes = rand(numNodes, 2) * 100;  % Fog nodes randomly placed within a 100x100 area

% Plot fog nodes
figure('Color','white');
scatter(fogNodes(:, 1), fogNodes(:, 2), 100, 'k', 'filled', 'MarkerEdgeColor', 'k'); % Plot fog nodes in black
title('Homogeneous Fog Network', 'FontSize', 14);
xlabel('X-axis', 'FontSize', 12);
ylabel('Y-axis', 'FontSize', 12);
axis equal;
grid on;

% Initialize trust matrix
trustMatrix = ones(numNodes, numNodes) * 0.5;

% Set diagonal elements to 1
trustMatrix(1:numNodes+1:end) = 1;

% Define parameters
numIterations = 200; % Number of iterations
packetSuccessRate = 0.5; % Probability of successful packet communication

% Nested loop for communication between nodes
for i = 1:numNodes
    for j = 1:numNodes
        if i ~= j % Exclude communication with itself
            % Communication loop for 100 packets
            for k = 1:numIterations
                % Randomly decide if packet is successfully communicated
                if rand() <= packetSuccessRate
                    % Packet successfully communicated
                    trustMatrix(i, j) = trustMatrix(i, j) + 0.0025; % Increase trust
                else
                    % Packet dropped
                    trustMatrix(i, j) = trustMatrix(i, j) - 0.0025; % Decrease trust
                end
            end
        end
    end
end

% Normalize trust matrix
trustMatrix = max(min(trustMatrix, 1), 0);

% Display updated trust matrix
disp('Trust Matrix:');
disp(trustMatrix);

% Initialize voting matrix
votingMatrix = zeros(numNodes);

% Populate voting matrix
for i = 1:numNodes
    [~, sortedIndices] = sort(trustMatrix(:, i));
    numNodes = size(trustMatrix, 1); % Ensure numNodes is correctly defined
    uniqueRanks = 1:numNodes; % Unique ranks in ascending order
    usedRanks = zeros(1, numNodes); % Track used ranks
    for j = 1:numNodes
        if i == j
            votingMatrix(j, i) = 0; % Set diagonal elements to 0
        else
            rank = find(sortedIndices == j); % Original rank
            adjustedRank = uniqueRanks(rank); % Adjusted rank
            while usedRanks(adjustedRank) % If the rank is already used
                adjustedRank = adjustedRank + 1; % Increment rank
            end
            usedRanks(adjustedRank) = 1; % Mark rank as used
            votingMatrix(j, i) = adjustedRank ; % Assign adjusted rank
        end
    end
end


% Display voting matrix
disp('Voting Matrix:');
disp(votingMatrix);

% Calculate Borda ranks
bordaScores = sum(votingMatrix,2);

% Display Borda ranks
disp('Borda Scores before Attack:');
disp(bordaScores);

% Define malicious nodes
numMalicious = round(0.3 * numNodes); % 30% of nodes are malicious
maliciousNodes = randperm(numNodes, numMalicious); % Randomly select malicious nodes


% Populate voting matrix
for i = 1:numNodes
    [~, sortedIndices] = sort(trustMatrix(:, i));
    numNodes = size(trustMatrix, 1); % Ensure numNodes is correctly defined
    uniqueRanks = 1:numNodes; % Unique ranks in ascending order
    usedRanks = zeros(1, numNodes); % Track used ranks
    for j = 1:numNodes
        if i == j
            votingMatrix(j, i) = 0; % Set diagonal elements to 0

        elseif ismember(i, maliciousNodes)
            % Malicious node ranks opposite to its trust
            trustRank = find(sortedIndices == j);
            % Assign rank in ascending order for malicious nodes
            adjustedRank = trustRank;
            while usedRanks(adjustedRank) % If the rank is already used
                adjustedRank = adjustedRank - 1; % Decrement rank to assign opposite direction
            end
            usedRanks(adjustedRank) = 1; % Mark rank as used
            votingMatrix(j, i) = numNodes-adjustedRank;

        else
            rank = find(sortedIndices == j); % Original rank
            adjustedRank = uniqueRanks(rank); % Adjusted rank
            while usedRanks(adjustedRank) % If the rank is already used
                adjustedRank = adjustedRank + 1; % Increment rank
            end
            usedRanks(adjustedRank) = 1; % Mark rank as used
            votingMatrix(j, i) = adjustedRank ; % Assign adjusted rank
        end
    end
end


% Display updated voting matrix with malicious nodes
disp('Updated Voting Matrix with Malicious Nodes:');
disp(votingMatrix);

% Calculate Borda ranks with malicious nodes
bordaScoresMalicious = sum(votingMatrix,2);

% Display Borda ranks with malicious nodes
disp('Borda Scores after Attack:');
disp(bordaScoresMalicious);

% Assign ranks based on Borda scores before attack
[~, rankBefore] = sort(bordaScores, 'descend');

% Display node number with corresponding rank before attack
disp('Node Ranks Before Attack:');
for i = 1:numNodes
    disp(['Node ', num2str(rankBefore(i)), ' : Rank ', num2str(i)]);
end

% Assign ranks based on Borda scores after the attack
[~, rankAfter] = sort(bordaScoresMalicious, 'descend');

% Display node number with corresponding rank after the attack
disp('Node Ranks After Attack:');
for i = 1:numNodes
    disp(['Node ', num2str(rankAfter(i)), ' : Rank ', num2str(i)]);
end

% Initialize array to store initial ranks before the attack
initialRanks = zeros(numNodes, 1);

% Populate initial ranks before the attack
for i = 1:numNodes
    initialRanks(i) = find(rankBefore == i);
end

% Initialize array to store rank changes for each node
rankChanges = zeros(numNodes, 1);

% Calculate rank changes for each node
for i = 1:numNodes
    finalRank = find(rankAfter == i);
    rankChanges(i) = initialRanks(i) - finalRank;
end

% Display rank changes for each node
disp('Rank Changes for Each Node:');
for i = 1:numNodes
    disp(['Node ', num2str(i), ' Change: ', num2str(rankChanges(i))]);
end


% Define the dimensions of the matrix
dimension = round(0.3 * numNodes);

% Initialize the matrix to store identified nodes
identifiedNodes = zeros(numNodes, dimension);

% Initialize array to store total sum of occurrences
occurrencesSum = zeros(1, numNodes);

% Initialize identifiedNodes matrix
identifiedNodes = zeros(numNodes, dimension);

% Identify nodes based on positive change in rank
for i = 1:numNodes
    if rankChanges(i) > 0 % If the rank increased
        % Get the i-th row of the matrix excluding the diagonal element
        row_i = votingMatrix(i, [1:i-1, i+1:end]);
        % Sort the elements of the row in descending order
        [~, sorted_indices] = sort(row_i, 'descend');
        % Adjust the indices to account for excluding the diagonal element
        adjusted_indices = sorted_indices(1:dimension) + (sorted_indices(1:dimension) >= i);
        identifiedNodes(i, :) = adjusted_indices;
    elseif rankChanges(i) < 0 % If the rank decreased
        % Get the i-th row of the matrix excluding the diagonal element
        row_i = votingMatrix(i, [1:i-1, i+1:end]);
        % Sort the elements of the row in ascending order
        [~, sorted_indices] = sort(row_i, 'ascend');
        % Adjust the indices to account for excluding the diagonal element
        adjusted_indices = sorted_indices(1:dimension) + (sorted_indices(1:dimension) >= i);
        identifiedNodes(i, :) = adjusted_indices;
    else % If the rank remained the same
        % Set identified nodes to zero
        identifiedNodes(i, :) = zeros(1, dimension);
    end
end

% Iterate through each row of identifiedNodes
for k = 1:size(identifiedNodes, 1)
    % Get the elements in the current row
    elements = identifiedNodes(k,:);
    % Increment the occurrences for each element
    for j = 1:numel(elements)
        if elements(j) ~= 0 % Check if element is non-zero
            occurrencesSum(elements(j)) = occurrencesSum(elements(j)) + abs(rankChanges(k));
        end
    end
end



% Display the matrix of identified nodes
disp('Identified Nodes Matrix:');
disp(identifiedNodes);

% Display the total sum of occurrences for each node
disp('Total sum of occurrences for each node:');
disp(occurrencesSum);
