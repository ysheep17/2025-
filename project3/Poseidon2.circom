pragma circom 2.0.0;

include "constants.circom";

template Poseidon2(t, d, fullRounds, partialRounds) {
    signal input preimage[t-1]; // 私有输入
    signal output digest;       // 公开输出

    var T = t;
    signal state[T];

    state[0] <== 0;
    for (var i = 1; i < T; i++) {
        state[i] <== preimage[i-1];
    }

    var roundIndex = 0;
    var halfFull = fullRounds / 2;

    function applyMDS(inState) -> (outState) {
        signal outState[T];
        for (var i = 0; i < T; i++) {
            signal acc;
            acc <== 0;
            for (var j = 0; j < T; j++) {
                acc <== acc + (MDS_CONST[i][j] * inState[j]);
            }
            outState[i] <== acc;
        }
        return outState;
    }

    function pow_d(x) -> (y) {
        if (d == 5) {
            signal x2; x2 <== x * x;
            signal x4; x4 <== x2 * x2;
            y <== x4 * x;
        } else if (d == 3) {
            signal x2; x2 <== x * x;
            y <== x2 * x;
        } else {
            signal acc; acc <== 1;
            for (var k = 0; k < d; k++) {
                acc <== acc * x;
            }
            y <== acc;
        }
    }

    // first half full rounds
    for (var r = 0; r < halfFull; r++) {
        for (var i = 0; i < T; i++) {
            state[i] <== state[i] + RC_CONST[roundIndex][i];
        }
        for (var i = 0; i < T; i++) {
            state[i] <== pow_d(state[i]);
        }
        state = applyMDS(state);
        roundIndex++;
    }

    // partial rounds
    for (var r = 0; r < partialRounds; r++) {
        for (var i = 0; i < T; i++) {
            state[i] <== state[i] + RC_CONST[roundIndex][i];
        }
        state[0] <== pow_d(state[0]);
        state = applyMDS(state);
        roundIndex++;
    }

    // second half full rounds
    for (var r = 0; r < halfFull; r++) {
        for (var i = 0; i < T; i++) {
            state[i] <== state[i] + RC_CONST[roundIndex][i];
        }
        for (var i = 0; i < T; i++) {
            state[i] <== pow_d(state[i]);
        }
        state = applyMDS(state);
        roundIndex++;
    }

    digest <== state[0];
}

component main = Poseidon2(3, 5, 8, 56); // 若 constants.json 有其它 round 数，请同步修改
