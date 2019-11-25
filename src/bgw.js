const mcl = require("mcl-wasm")
const assert = require("assert")

function bgw05 () {
  // https://eprint.iacr.org/2005/018.pdf

  // Setup

  // public key
  let hrstart = process.hrtime()

  const g_G1 = mcl.hashAndMapToG1('1')
  let PK_G1 = []
  PK_G1.push(g_G1)

  const g_G2 = mcl.hashAndMapToG2('1')
  let PK_G2 = []
  PK_G2.push(g_G2)


  const alpha = new mcl.Fr()
  alpha.setByCSPRNG()

  const n = 10000 // number of users in the system
  console.log('number of users='+n)
  let alpha_i = alpha
  for (let i = 1; i <= 2 * n; i++) {
    if (i == n + 1) {
      PK_G1.push(0)
      PK_G2.push(0)
    } else {
      PK_G1.push(mcl.mul(g_G1, alpha_i))
      PK_G2.push(mcl.mul(g_G2, alpha_i))
    }
    alpha_i = mcl.mul(alpha_i, alpha)
  }
  const gamma = new mcl.Fr()  // In the general construction, each shard has a different gamma
  gamma.setByCSPRNG()
  const v_G1 = mcl.mul(g_G1, gamma)
  PK_G1.push(v_G1)
  const v_G2 = mcl.mul(g_G2, gamma)
  PK_G2.push(v_G2)

  let hrend = process.hrtime(hrstart)
  console.log('setup %d usec per user', (hrend[0]*1000000 + hrend[1] / 1000)/n)

  let PK_length = 0
  for (const p of PK_G1) {
    if (p != 0) {
      PK_length += p.serializeToHexStr().length
    }
  }
  console.log('PK length='+PK_length/2+' bytes '+PK_length/2/n+' bytes per user')

  // private keys
  let d_G1 = [0]
  for (let i = 1; i <= n; i++) {
    d_G1.push(mcl.mul(PK_G1[i], gamma))
  }

  // Encryption

  // generate a random broadcasting list
  const S = []
  for (let i = 1; i <= n; i++) {
    if (Math.random() > 0.5) {
      S.push(i)
    }
  }

  hrstart = process.hrtime()

  const t = new mcl.Fr()
  t.setByCSPRNG()
  const K_encrypt = mcl.pow(mcl.pairing(PK_G1[n], PK_G2[1]), t)
//  console.log('encryption key=' + K_encrypt.serializeToHexStr())

  let C_G2 = []
  C_G2.push(mcl.mul(g_G2, t))

  let c1_G2 = v_G2
  for (const j of S) {
    c1_G2 = mcl.add(c1_G2, PK_G2[n + 1 - j])
  }
  c1_G2 = mcl.mul(c1_G2, t)
  C_G2.push(c1_G2)
  hrend = process.hrtime(hrstart)
  console.log('encrypt %d usec per S user', (hrend[0]*1000000 + hrend[1] / 1000)/S.length)

  // Decrypt
  hrstart = process.hrtime()

  let ntrials = 5
  for (let k = 1; k <= ntrials; k++) { // iterate overuser doing the decryption
    let i = Math.ceil(Math.random() * n)  // select user
    // console.log('user='+i)
    let e_G1 = d_G1[i]

    for (const j of S) {
      if (j != i) {
        e_G1 = mcl.add(e_G1, PK_G1[n + 1 - j + i])
      }
    }

    const K_decrypt = mcl.div(mcl.pairing(PK_G1[i], C_G2[1]), mcl.pairing(e_G1, C_G2[0]))
    // console.log('decryption key=' + K_decrypt.serializeToHexStr())
    if (S.includes(i)) {
      assert.equal(K_decrypt.serializeToHexStr(), K_encrypt.serializeToHexStr(),'user='+i)
    } else {
      assert.notEqual(K_decrypt.serializeToHexStr(), K_encrypt.serializeToHexStr(),'user='+i)
    }
  }

  hrend = process.hrtime(hrstart)
  console.log('decrypt %d usec per S user', (hrend[0]*1000000 + hrend[1] / 1000)/ntrials/S.length)

  // number of users=400000
  // PK length=25600032 bytes 64.00008 bytes per user
  // setup 2436.2948255875 usec per user
  // encrypt 11.270703551057405 usec per S user
  // decrypt 3.908505978856911 usec per S user

}

async function main() {
  await mcl.init()  // use default curve BN254
  console.log('init')
  bgw05()
}

main().then(()=> {
  console.log('done')
})
