Python tools for the following:
- Generate CNF for time reversal
- Load CNF
- Pass output bits and solve for possible keys

// THis seems to work well for generation
// outputs is variable
./grainofsalt --outputs 50 --crypto crypto1 --karnaugh 8 --xorclauses --nopropagate

When loading
- Extract variable IDs of outputs
- Extract variable IDs of SR[0][0:47]
- Clauses that define output literals are removed on loading

Solving
- Observed outputs are passed to partially loaded model as literal clauses
- SAT solver then solves for possible SR[0][0]-SR[0][47] state
- Array of possible keys is produced


