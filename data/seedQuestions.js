export const SEED_QUESTION_BANK = {
    'Logical Reasoning': [
        {
            difficulty: 'easy',
            question: 'What comes next in the sequence 2, 4, 8, 16, ?',
            options: ['18', '24', '32', '20'],
            answer: '32',
            explanation: 'Each term doubles, so the next value is 32.'
        },
        {
            difficulty: 'easy',
            question: 'Choose the odd one out: Apple, Banana, Carrot, Grape.',
            options: ['Apple', 'Banana', 'Carrot', 'Grape'],
            answer: 'Carrot',
            explanation: 'Carrot is a vegetable while the others are fruits.'
        },
        {
            difficulty: 'medium',
            question: 'If all coders are problem solvers and some problem solvers are designers, which statement must be true?',
            options: ['All coders are designers', 'Some problem solvers are designers', 'No designer is a coder', 'All designers are coders'],
            answer: 'Some problem solvers are designers',
            explanation: 'That statement is directly given in the premise.'
        },
        {
            difficulty: 'medium',
            question: 'A clock shows 3:15. What is the angle between the hour and minute hands?',
            options: ['0 degrees', '7.5 degrees', '15 degrees', '22.5 degrees'],
            answer: '7.5 degrees',
            explanation: 'The hour hand moves between 3 and 4, creating a 7.5 degree offset from the minute hand.'
        },
        {
            difficulty: 'hard',
            question: 'Find the missing number: 3, 7, 15, 31, ?',
            options: ['47', '57', '63', '71'],
            answer: '63',
            explanation: 'Each term is previous term x 2 + 1.'
        },
        {
            difficulty: 'hard',
            question: 'If six machines make six parts in six minutes, how many minutes will twelve machines take to make twenty-four parts?',
            options: ['6', '9', '12', '18'],
            answer: '12',
            explanation: 'Each machine makes one part every six minutes, so twelve machines make twelve parts in six minutes and twenty-four parts in twelve minutes.'
        }
    ],
    'Coding & Problem-Solving': [
        {
            difficulty: 'easy',
            question: 'What is the time complexity of accessing an array element by index?',
            options: ['O(1)', 'O(log n)', 'O(n)', 'O(n log n)'],
            answer: 'O(1)',
            explanation: 'Array indexing is constant time because the address is computed directly.'
        },
        {
            difficulty: 'easy',
            question: 'Which data structure uses Last In, First Out ordering?',
            options: ['Queue', 'Stack', 'Heap', 'Graph'],
            answer: 'Stack',
            explanation: 'A stack pops the most recently pushed value first.'
        },
        {
            difficulty: 'medium',
            question: 'Which traversal of a binary search tree returns values in sorted order?',
            options: ['Preorder', 'Postorder', 'Inorder', 'Level order'],
            answer: 'Inorder',
            explanation: 'Inorder traversal visits left subtree, root, then right subtree.'
        },
        {
            difficulty: 'medium',
            question: 'What is the main advantage of using dynamic programming?',
            options: ['Avoids recursion entirely', 'Reuses overlapping subproblems', 'Sorts input automatically', 'Eliminates memory usage'],
            answer: 'Reuses overlapping subproblems',
            explanation: 'Dynamic programming stores intermediate results to avoid repeated work.'
        },
        {
            difficulty: 'hard',
            question: 'Which technique is most appropriate for finding the shortest path in an unweighted graph?',
            options: ['Depth-first search', 'Breadth-first search', 'Binary search', 'Merge sort'],
            answer: 'Breadth-first search',
            explanation: 'BFS explores level by level and guarantees the shortest path in unweighted graphs.'
        },
        {
            difficulty: 'hard',
            question: 'Which sorting algorithm is stable in its common implementation?',
            options: ['Heap sort', 'Quick sort', 'Merge sort', 'Selection sort'],
            answer: 'Merge sort',
            explanation: 'Merge sort preserves the relative order of equal elements.'
        }
    ],
    'Quantitative Aptitude': [
        {
            difficulty: 'easy',
            question: 'If 5x - 3 = 17, what is x?',
            options: ['2', '3', '4', '5'],
            answer: '4',
            explanation: 'Add 3 to both sides and divide by 5.'
        },
        {
            difficulty: 'easy',
            question: 'What is 25% of 480?',
            options: ['100', '110', '120', '140'],
            answer: '120',
            explanation: 'Twenty-five percent is one-fourth, and one-fourth of 480 is 120.'
        },
        {
            difficulty: 'medium',
            question: 'A train travels 120 km in 2 hours. What is its average speed?',
            options: ['50 km/h', '55 km/h', '60 km/h', '65 km/h'],
            answer: '60 km/h',
            explanation: 'Average speed equals distance divided by time.'
        },
        {
            difficulty: 'medium',
            question: 'The ratio of boys to girls in a class is 3:2. If there are 30 students, how many are girls?',
            options: ['10', '12', '15', '18'],
            answer: '12',
            explanation: 'Two-fifths of 30 is 12.'
        },
        {
            difficulty: 'hard',
            question: 'A man walks 30 km at 5 km/h and returns at 6 km/h. What is his average speed for the whole trip?',
            options: ['5.25 km/h', '5.45 km/h', '5.5 km/h', '6 km/h'],
            answer: '5.45 km/h',
            explanation: 'Average speed over equal distances is 2ab/(a+b).'
        },
        {
            difficulty: 'hard',
            question: 'If the compound interest on a sum for 2 years at 10% per annum is 231, what is the principal?',
            options: ['1000', '1100', '1200', '1500'],
            answer: '1100',
            explanation: 'For 2 years at 10%, compound interest is 21% of principal, so principal is 231 / 0.21.'
        }
    ],
    'CS Fundamentals': [
        {
            difficulty: 'easy',
            question: 'Which OSI layer is responsible for routing packets?',
            options: ['Transport', 'Network', 'Data Link', 'Application'],
            answer: 'Network',
            explanation: 'Routing decisions happen at the network layer.'
        },
        {
            difficulty: 'easy',
            question: 'Which SQL command is used to retrieve data from a table?',
            options: ['GET', 'FETCH', 'SELECT', 'READ'],
            answer: 'SELECT',
            explanation: 'SELECT is the standard query command in SQL.'
        },
        {
            difficulty: 'medium',
            question: 'What does normalization in DBMS primarily reduce?',
            options: ['Network latency', 'Data redundancy', 'CPU frequency', 'Index size'],
            answer: 'Data redundancy',
            explanation: 'Normalization organizes data to reduce duplication and anomalies.'
        },
        {
            difficulty: 'medium',
            question: 'Which scheduling algorithm can cause starvation for low-priority processes?',
            options: ['Round Robin', 'FCFS', 'Priority Scheduling', 'Shortest Job First'],
            answer: 'Priority Scheduling',
            explanation: 'Lower-priority processes can wait indefinitely when higher-priority work keeps arriving.'
        },
        {
            difficulty: 'hard',
            question: 'Which concurrency issue occurs when two or more processes wait forever for resources held by each other?',
            options: ['Thrashing', 'Deadlock', 'Starvation', 'Fragmentation'],
            answer: 'Deadlock',
            explanation: 'Deadlock is circular waiting with no progress.'
        },
        {
            difficulty: 'hard',
            question: 'Which indexing structure is commonly used by databases for efficient range queries?',
            options: ['Hash table', 'B-tree', 'Stack', 'Queue'],
            answer: 'B-tree',
            explanation: 'B-trees support sorted traversal and efficient range scans.'
        }
    ],
    'Verbal & Communication': [
        {
            difficulty: 'easy',
            question: 'Choose the correctly spelled word.',
            options: ['Definately', 'Definitely', 'Definetly', 'Definatly'],
            answer: 'Definitely',
            explanation: 'Definitely is the correct spelling.'
        },
        {
            difficulty: 'easy',
            question: 'Choose the synonym of "brief".',
            options: ['Lengthy', 'Short', 'Loud', 'Harsh'],
            answer: 'Short',
            explanation: 'Brief means short in duration or length.'
        },
        {
            difficulty: 'medium',
            question: 'Choose the sentence with correct subject-verb agreement.',
            options: ['The list of items are on the desk.', 'The list of items is on the desk.', 'The list of items were on the desk.', 'The list of items be on the desk.'],
            answer: 'The list of items is on the desk.',
            explanation: 'The subject is list, which is singular.'
        },
        {
            difficulty: 'medium',
            question: 'Choose the antonym of "abundant".',
            options: ['Plentiful', 'Scarce', 'Ample', 'Adequate'],
            answer: 'Scarce',
            explanation: 'Scarce means limited or insufficient.'
        },
        {
            difficulty: 'hard',
            question: 'Identify the sentence written in active voice.',
            options: ['The proposal was approved by the board.', 'The board approved the proposal.', 'The proposal had been approved.', 'The approval was granted.'],
            answer: 'The board approved the proposal.',
            explanation: 'The subject performs the action directly in active voice.'
        },
        {
            difficulty: 'hard',
            question: 'Choose the best replacement for the underlined phrase: "She is capable to finish the project on time."',
            options: ['capable for finishing', 'capable of finishing', 'capable with finishing', 'capable at finish'],
            answer: 'capable of finishing',
            explanation: 'The correct collocation is capable of followed by a gerund.'
        }
    ],
    'Mock Tests & Assessments': [
        {
            difficulty: 'easy',
            question: 'In an aptitude round, which strategy is usually best first?',
            options: ['Attempt the hardest questions first', 'Skip reading instructions', 'Start with high-confidence questions', 'Spend equal time on every question'],
            answer: 'Start with high-confidence questions',
            explanation: 'Quick wins improve score and time management in timed tests.'
        },
        {
            difficulty: 'easy',
            question: 'What is a good way to reduce errors in online assessments?',
            options: ['Change answers randomly', 'Ignore time left', 'Review flagged questions', 'Submit early without checking'],
            answer: 'Review flagged questions',
            explanation: 'A short review helps catch avoidable mistakes.'
        },
        {
            difficulty: 'medium',
            question: 'During a proctored assessment, what should you do if your network becomes unstable?',
            options: ['Close the test window immediately', 'Open multiple tabs to test speed', 'Follow the platform instructions and reconnect calmly', 'Refresh continuously'],
            answer: 'Follow the platform instructions and reconnect calmly',
            explanation: 'Most platforms record state and provide a guided recovery path.'
        },
        {
            difficulty: 'medium',
            question: 'A mock test has 60 questions in 45 minutes. What is the average time per question?',
            options: ['30 seconds', '45 seconds', '60 seconds', '75 seconds'],
            answer: '45 seconds',
            explanation: 'Forty-five minutes equals 2700 seconds, and 2700 divided by 60 is 45.'
        },
        {
            difficulty: 'hard',
            question: 'Which metric is most useful when analyzing mock test performance over time?',
            options: ['Only the final score', 'Accuracy by topic and time spent', 'Screen brightness', 'Keyboard speed alone'],
            answer: 'Accuracy by topic and time spent',
            explanation: 'That combination helps identify both knowledge gaps and pacing problems.'
        },
        {
            difficulty: 'hard',
            question: 'If negative marking is -0.25 and a question has a 25% guess probability, what is the expected value of a random guess when a correct answer gives +1?',
            options: ['Positive', 'Zero', 'Negative', 'Cannot be determined'],
            answer: 'Positive',
            explanation: 'Expected value is 0.25 x 1 plus 0.75 x -0.25, which equals 0.0625, so the guess is slightly positive.'
        }
    ]
};
