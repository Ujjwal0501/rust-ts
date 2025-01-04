// import { CurveType } from '@noble/curves/abstract/bls';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { Buffer } from 'buffer';
import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { Fp, Fp12, Fp2, } from '@noble/curves/abstract/tower';

/**
 * Summary of porting the Silent Threshold encryption scheme from Rust to JavaScript.
 * 
 * The Silent Threshold encryption scheme is a threshold encryption scheme that uses BLS12-381 as the underlying elliptic curve.
 * The scheme is based on the BLS signature scheme and uses the BLS pairing to encrypt and decrypt data.
 * 
 * The types ported from the original Rust implementation are:
 * - E::ScalarField -> BigInt
 * - QuadExtField   -> Fp2
 * - CubicExtField  -> Fp6
 * - E::G1          -> ProjPointType<Fp>
 * - E::G2          -> ProjPointType<Fp2>
 * - PairingOutput  -> ProjPointType<Fp12>
 */

/**
 * @typedef {Object} PublicKey
 * @property {number} id - The identifier for the public key.
 * @property {ProjPointType<Fp>} bls_pk - The BLS public key.
 * @property {ProjPointType<Fp>} sk_li - The secret key component li.
 * @property {ProjPointType<Fp>} sk_li_minus0 - The secret key component li minus 0.
 * @property {ProjPointType<Fp>} sk_li_x - The secret key component li x.
 * @property {Array<ProjPointType<Fp>>} sk_li_lj_z - The secret key components li lj z.
 */
type PublicKey = {
    id: number,
    bls_pk: ProjPointType<Fp>,
    sk_li: ProjPointType<Fp>,             //hint
    sk_li_minus0: ProjPointType<Fp>,      //hint
    sk_li_lj_z: Array<ProjPointType<Fp>>, //hint
    sk_li_x: ProjPointType<Fp>,           //hint
}

/**
 * @typedef {Object} LagrangePowers
 * @property {Array<CurveType>} li - The Lagrange coefficients li.
 * @property {Array<ProjPointType<Fp>>} li_minus0 - The Lagrange coefficients li minus 0.
 * @property {Array<ProjPointType<Fp>>} li_x - The Lagrange coefficients li x.
 * @property {Array<Array<ProjPointType<Fp>>>} li_lj_z - The Lagrange coefficients li lj z.
 */
type LagrangePowers = {
    // li: Array<CurveType>,
    li_minus0: Array<ProjPointType<Fp>>,
    li_x: Array<ProjPointType<Fp>>,
    li_lj_z: Array<Array<ProjPointType<Fp>>>,
}

/**
 * @typedef {ProjPointType<Fp12>} PairingOutput - The output of the pairing operation.
 */
type PairingOutput = ProjPointType<Fp12>;

/**
 * @typedef {Object} AggregateKey
 * @property {Array<PublicKey>} pk - The array of public keys.
 * @property {Array<ProjPointType<Fp>>} agg_sk_li_lj_z - The aggregated secret key components li lj z.
 * @property {ProjPointType<Fp>} ask - The aggregated secret key.
 * @property {ProjPointType<Fp2>} z_g2 - The z_g2 component.
 * @property {ProjPointType<Fp2>} h_minus1 - The h_minus1 component.
 * @property {PairingOutput} e_gh - The preprocessed pairing output.
 */
type AggregateKey = {
    pk: Array<PublicKey>,
    agg_sk_li_lj_z: Array<ProjPointType<Fp>>,
    ask: ProjPointType<Fp>,
    z_g2: ProjPointType<Fp2>,

    //preprocessed values
    h_minus1: ProjPointType<Fp2>,
    e_gh: Fp12,
}

/**
 * @typedef {Object} Ciphertext
 * @property {ProjPointType<Fp2>} gamma_g2 - The gamma_g2 component.
 * @property {Array<ProjPointType<Fp>>} sa1 - The sa1 components (2 elements).
 * @property {Array<ProjPointType<Fp2>>} sa2 - The sa2 components (6 elements).
 * @property {PairingOutput} enc_key - The encryption key.
 * @property {number} t - The threshold value.
 */
type Ciphertext = {
    gamma_g2: ProjPointType<Fp2>,
    sa1: ProjPointType<Fp>[],
    sa2: ProjPointType<Fp2>[],
    enc_key: Fp12, // key to be used for encapsulation
    t: number,              // threshold
}

/**
 * @typedef {Object} PowersOfTau
 * @property {ArrayLike<ProjPointType<Fp>>} powers_of_g - The powers of g.
 * @property {ArrayLike<ProjPointType<Fp2>>} powers_of_h - The powers of h.
 */
type PowersOfTau = {
    powers_of_g: ArrayLike<ProjPointType<Fp>>,
    powers_of_h: ArrayLike<ProjPointType<Fp2>>,
}

/**
 * Encrypts data using the provided parameters and aggregate public key.
 *
 * @param params - The PowersOfTau parameters containing powers of g and h.
 * @param apk - The AggregateKey containing the aggregated public key and preprocessed values.
 * @param t - The threshold value for encryption.
 * @returns A Ciphertext object containing the encrypted data.
 */
const encrypt = (params: PowersOfTau, apk: AggregateKey, t: number) => {
    // Initialize an ArrayBuffer (tau) from a fixed string
    const gamma = bls.G1.normPrivateKeyToScalar('99173daeb1c2bd38993e379ad5b761a88de97c3ba38b1335e5828f8f30788a4d');
    // const gamma = bls.G1.normPrivateKeyToScalar(bls.utils.randomPrivateKey());
    const gamma_g2 = bls.G2.ProjectivePoint.BASE.multiply(gamma);

    let g = bls.G1.ProjectivePoint.BASE;
    let h = bls.G2.ProjectivePoint.BASE;

    let sa1 = [g, g];
    let sa2: ProjPointType<Fp2>[] = Array(6).fill(h);

    const hexValues = [
        'c1c11f354976fcd12b511f2926346725c96abaaac9f1bf33da92c1bbcb87f434',
        '0f73503ec79f0facb0ec92d92ca7a2405905bed63049a6d47b77a022d23b3e0d',
        'dfad9c2cb7393f80c275a99c88591e97c8f49cf4f3952645382890587e2a6137',
        '5dc4a5352d60d1b65f5749bd75bbd4bed9a56d47f1c056cf217488752fc9e04b',
        '7d7c26f5c96021a4864c5885d27f62efe021830a5e127e16ab623f31ae4f1a56'
    ];

    let s = hexValues.map(hex => bls.G1.normPrivateKeyToScalar(hex));
    // const s = Array.from({ length: 5 }, () => bls.G1.normPrivateKeyToScalar(bls.utils.randomPrivateKey()));

    // sa1[0] = s0*ask + s3*g^{tau^t} + s4*g
    sa1[0] = apk.ask.multiply(s[0])
        .add(g.multiply(BigInt(t)).multiply(s[3]))
        .add(g.multiply(s[4]));

    // sa1[1] = s2*g
    sa1[1] = g.multiply(s[2]);

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = h.multiply(s[0])
        .add(gamma_g2.multiply(s[2]));

    // sa2[1] = s0*z_g2
    sa2[1] = apk.z_g2.multiply(s[0]);

    // sa2[2] = s0*h^tau + s1*h^tau
    sa2[2] = h.multiply(s[0])
        .add(h.multiply(s[1]));

    // sa2[3] = s1*h
    sa2[3] = h.multiply(s[1]);

    // sa2[4] = s3*h
    sa2[4] = h.multiply(s[3]);

    // sa2[5] = s4*h^{tau - omega^0}
    sa2[5] = params.powers_of_h[1]
        .add(apk.h_minus1)
        .multiply(s[4]);

    // enc_key = s4*e_gh
    const enc_key = bls.fields.Fp12.mul(apk.e_gh, s[4]);
    // const enc_key = apk.e_gh.multiply(s[4]);

    return { gamma_g2, sa1, sa2, enc_key, t };
}

/**
 * Decodes a hex string into a PowersOfTau object.
 *
 * @param input - The hex string to decode.
 * @returns A PowersOfTau object containing the decoded data.
 */
const decodePowersOfTau = (input: string): PowersOfTau => {
    const buffer = Buffer.from(input, 'hex');
    const powers_of_g: Array<ProjPointType<Fp>> = [];
    const powers_of_h: Array<ProjPointType<Fp2>> = [];

    // Assuming each point is 96 bytes for G1 and 192 bytes for G2
    const G1_POINT_SIZE = 96 / 2;
    const G2_POINT_SIZE = 192 / 2;

    let offset = 0;

    // Decode the 64-bit little-endian count from the input
    const count = buffer.readBigUInt64LE(offset);
    offset += 8;

    // Decode powers_of_g
    for (let i = 0; i < count; i++) {
        const pointBuffer = buffer.slice(offset, offset + G1_POINT_SIZE);
        const point = bls.G1.ProjectivePoint.fromHex(new Uint8Array(pointBuffer));
        powers_of_g.push(point);
        offset += G1_POINT_SIZE;
    }

    // Decode the 64-bit little-endian count from the input
    offset += 8;

    // Decode powers_of_h
    for (let i = 0; i < count; i++) {
        const pointBuffer = buffer.slice(offset, offset + G2_POINT_SIZE);
        const point = bls.G2.ProjectivePoint.fromHex(new Uint8Array(pointBuffer));
        powers_of_h.push(point);
        offset += G2_POINT_SIZE;
    }

    return { powers_of_g, powers_of_h };
};

/**
 * Decodes a hex string into an AggregateKey object.
 *
 * @param input - The hex string to decode.
 * @returns An AggregateKey object containing the decoded data.
 */
const decodeAggregateKey = (input: string): AggregateKey => {
    const buffer = Buffer.from(input, 'hex');
    let offset = 0;

    const readBigUInt64LE = () => {
        const value = buffer.readBigUInt64LE(offset);
        offset += 8;
        return value;
    };

    const readProjPointTypeFp = (count: bigint) => {
        const points: Array<ProjPointType<Fp>> = [];
        for (let i = 0; i < count; i++) {
            const pointBuffer = buffer.slice(offset, offset + 48);
            console.log(pointBuffer);
            console.log(BigInt('0x' + pointBuffer.toString('hex')));
            const point = bls.G1.ProjectivePoint.fromHex(new Uint8Array(pointBuffer));
            points.push(point);
            offset += 48;
        }
        return points;
    };

    const readProjPointTypeFp2 = (count: bigint) => {
        const points: Array<ProjPointType<Fp2>> = [];
        for (let i = 0; i < count; i++) {
            const pointBuffer = buffer.slice(offset, offset + 96);
            const point = bls.G2.ProjectivePoint.fromHex(new Uint8Array(pointBuffer));
            points.push(point);
            offset += 96;
        }
        return points;
    };

    const readProjPointTypeFp12 = () => {
        const points: Array<Fp> = [];
        for (let i = 0; i < 12; i++) {
            const pointBuffer = buffer.slice(offset, offset + 48);
            const point = BigInt('0x' + pointBuffer.toString('hex'));
            points.push(point);
            offset += 48;
        }
        if (points.length !== 12) {
            throw new Error('Invalid number of points for Fp12');
        }
        // return bls.fields.Fp12.fromBigTwelve(points as [bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint]);
        return bls.fields.Fp12.create({
            c0: bls.fields.Fp6.create({c0: bls.fields.Fp2.create({c0: points[0], c1: points[1]}), c1: bls.fields.Fp2.create({c0: points[2], c1: points[3]}), c2: bls.fields.Fp2.create({c0: points[4], c1: points[5]})}),
            c1: bls.fields.Fp6.create({c0: bls.fields.Fp2.create({c0: points[6], c1: points[7]}), c1: bls.fields.Fp2.create({c0: points[8], c1: points[9]}), c2: bls.fields.Fp2.create({c0: points[10], c1: points[11]})})
        });
    };

    const pkCount = readBigUInt64LE();
    const pk: Array<PublicKey> = [];
    for (let i = 0; i < pkCount; i++) {
        const id = Number(readBigUInt64LE());
        const bls_pk = readProjPointTypeFp(BigInt(1))[0];
        const sk_li = readProjPointTypeFp(BigInt(1))[0];
        const sk_li_minus0 = readProjPointTypeFp(BigInt(1))[0];
        const sk_li_lj_z = readProjPointTypeFp(readBigUInt64LE());
        const sk_li_x = readProjPointTypeFp(BigInt(1))[0];
        pk.push({ id, bls_pk, sk_li, sk_li_minus0, sk_li_x, sk_li_lj_z });
    }

    const agg_sk_li_lj_z = readProjPointTypeFp(readBigUInt64LE());
    const ask = readProjPointTypeFp(BigInt(1))[0];
    const z_g2 = readProjPointTypeFp2(BigInt(1))[0];
    const h_minus1 = readProjPointTypeFp2(BigInt(1))[0];
    const e_gh = readProjPointTypeFp12();

    return { pk, agg_sk_li_lj_z, ask, z_g2, h_minus1, e_gh };
};

/**
 * Encode a Ciphertext object into a hex string.
 *
 * @param input - The Ciphertext object to encode.
 * @returns A hex string containing the encoded data.
 */
const encodeCiphertext = (input: Ciphertext): string => {
    const buffer = Buffer.alloc(0);
    const writeProjPointTypeFp = (point: ProjPointType<Fp>) => {
        const hex = point.toHex(true);
        return Buffer.from(hex, 'hex');
    };

    const writeProjPointTypeFp2 = (point: ProjPointType<Fp2>) => {
        const hex = point.toHex(true);
        return Buffer.from(hex, 'hex');
    };

    const writeProjPointTypeFp12 = (point: Fp12) => {
        const hex = bls.fields.Fp12.toBytes(point);
        // const hex = point.toHex();
        return Buffer.from(hex);
    };

    const gamma_g2Buffer = writeProjPointTypeFp2(input.gamma_g2);
    const sa1Buffer = Buffer.concat(input.sa1.map(writeProjPointTypeFp));
    const sa2Buffer = Buffer.concat(input.sa2.map(writeProjPointTypeFp2));
    const enc_keyBuffer = Buffer.from(fp12ToHex(input.enc_key));
    const tBuffer = Buffer.alloc(4);
    tBuffer.writeUInt32LE(input.t, 0);

    const sa1LengthBuffer = Buffer.alloc(8);
    sa1LengthBuffer.writeBigUInt64LE(BigInt(input.sa1.length), 0);

    const sa2LengthBuffer = Buffer.alloc(8);
    sa2LengthBuffer.writeBigUInt64LE(BigInt(input.sa2.length), 0);

    const totalLength = gamma_g2Buffer.length + sa1LengthBuffer.length + sa1Buffer.length + sa2LengthBuffer.length + sa2Buffer.length + enc_keyBuffer.length + tBuffer.length;

    const resultBuffer = Buffer.concat([gamma_g2Buffer, sa1LengthBuffer, sa1Buffer, sa2LengthBuffer, sa2Buffer, enc_keyBuffer, tBuffer], totalLength);
    // const resultBuffer = Buffer.concat([gamma_g2Buffer, sa1Buffer, sa2Buffer, enc_keyBuffer, tBuffer], totalLength);
    console.log(enc_keyBuffer.toString('hex'));

    return resultBuffer.toString('hex');
}


function demoFieldOperations() {
    // Create base points in G1 and G2
    const g1Base = bls.G1.ProjectivePoint.BASE;
    const g2Base = bls.G2.ProjectivePoint.BASE;
    console.log('G1 generator: ', g1Base.toHex(true));
    console.log('G2 generator: ', g2Base.toHex(true));

    const e_ghH = bls.pairing(g1Base, g2Base);
    console.log(fp12ToHex(e_ghH));
    // return

    // Perform G1 addition
    const g1Sum = g1Base.add(g1Base);
    console.log('G1 generator doubled: ', g1Sum.toHex(true));

    // Perform G2 addition
    const g2Sum = g2Base.add(g2Base);
    console.log('G2 generator doubled: ', g2Sum.toHex(true));

    // Create an Fp element and do multiplication
    const fp_a = bls.fields.Fp.create(BigInt('0xa191b705ef18a6e4e5bd4cc56de0b8f94b1f3c908f3e3fcbd4d1dc12eb85059be7e7d801edc1856c8cfbe6d63a681c1f'));
    const fp_b = bls.fields.Fp.create(BigInt('0x8e07730c0dceb35342bfa587940babad2ec7622aec96994179086a5d323c479e64c890939e47f9a46b427f063f71d4f4'));
    const fpModified = bls.fields.Fp.addN(fp_a, fp_b);
    console.log('Fp a + b: ', fpModified.toString(16));

    const g1_a = bls.G1.ProjectivePoint.fromHex('a191b705ef18a6e4e5bd4cc56de0b8f94b1f3c908f3e3fcbd4d1dc12eb85059be7e7d801edc1856c8cfbe6d63a681c1f');
    const g1_b = bls.G1.ProjectivePoint.fromHex('8e07730c0dceb35342bfa587940babad2ec7622aec96994179086a5d323c479e64c890939e47f9a46b427f063f71d4f4');
    const g1_zero = bls.G1.ProjectivePoint.ZERO;
    console.log('G1 a: ', g1_a.toHex(true));
    console.log('G1 b: ', g1_b.toHex(true));
    console.log('G1 zero: ', g1_zero.toHex(true));

    const g1_sum = g1_a.add(g1_b);
    const g1_sub = g1_a.subtract(g1_b);
    const g1_neg = g1_a.negate();
    const g1_dbl = g1_a.double();
    console.log('G1 a + b: ', g1_sum.toHex(true));
    console.log('G1 a - b: ', g1_sub.toHex(true));
    console.log('G1 -a: ', g1_neg.toHex(true));
    console.log('G1 2a: ', g1_dbl.toHex(true));

    // Create an Fp2 element and do multiplication
    const fp2_a = bls.fields.Fp2.create({c0: BigInt('0x848e9f7ae435bd738c33ae1f11cefb472b29a090de5ce00740b8ec1bd30fdbb27eb7e65162eed68c55e0bb03bf749857'), c1: BigInt('0x0f8faa02f0dd3225ca98d8306f8efa4e3f62a13efc342f3466d3e56be5144dae68cafab0f99ddf1f04a6659806b12235')});
    const fp2_b = bls.fields.Fp2.create({c0: BigInt('0xa4d21fc0921dcca8f0666f3b7530b569c2309bc13d3303a6fc3d233c58275972879c415608b6774bbbb00e10a6e47ace'), c1: BigInt('0x1046aa2e6208f5d1813de823e5e3dec638bb7b82247cebeebbc70a14f1f59b9c0738b0f08120cb81d8c876579bd2391f')});
    const fp2Modified = bls.fields.Fp2.addN(fp2_a, fp2_b);
    console.log('Fp2 a + b: ', fp2Modified.c0.toString(16), fp2Modified.c1.toString(16));

    const g2_a = bls.G2.ProjectivePoint.fromHex('848e9f7ae435bd738c33ae1f11cefb472b29a090de5ce00740b8ec1bd30fdbb27eb7e65162eed68c55e0bb03bf7498570f8faa02f0dd3225ca98d8306f8efa4e3f62a13efc342f3466d3e56be5144dae68cafab0f99ddf1f04a6659806b12235');
    const g2_b = bls.G2.ProjectivePoint.fromHex('a4d21fc0921dcca8f0666f3b7530b569c2309bc13d3303a6fc3d233c58275972879c415608b6774bbbb00e10a6e47ace1046aa2e6208f5d1813de823e5e3dec638bb7b82247cebeebbc70a14f1f59b9c0738b0f08120cb81d8c876579bd2391f');
    const g2_zero = bls.G2.ProjectivePoint.ZERO;
    console.log('G2 a: ', g2_a.toHex(true));
    console.log('G2 b: ', g2_b.toHex(true));
    console.log('G2 zero: ', g2_zero.toHex(true));

    const g2_sum = g2_a.add(g2_b);
    const g2_sub = g2_a.subtract(g2_b);
    const g2_neg = g2_a.negate();
    const g2_dbl = g2_a.double();
    console.log('G2 a + b: ', g2_sum.toHex(true));
    console.log('G2 a - b: ', g2_sub.toHex(true));
    console.log('G2 -a: ', g2_neg.toHex(true));
    console.log('G2 2a: ', g2_dbl.toHex(true));

    // Create an Fp12 element and do squaring
    const someFp12 = bls.fields.Fp12.create({
        c0: bls.fields.Fp6.create({
            c0: bls.fields.Fp2.create({ c0: BigInt(1), c1: BigInt(0) }),
            c1: bls.fields.Fp2.create({ c0: BigInt(0), c1: BigInt(1) }),
            c2: bls.fields.Fp2.create({ c0: BigInt(2), c1: BigInt(3) })
        }),
        c1: bls.fields.Fp6.create({
            c0: bls.fields.Fp2.create({ c0: BigInt(4), c1: BigInt(5) }),
            c1: bls.fields.Fp2.create({ c0: BigInt(6), c1: BigInt(7) }),
            c2: bls.fields.Fp2.create({ c0: BigInt(8), c1: BigInt(9) })
        })
    });
    const fp12Squared = bls.fields.Fp12.mul(someFp12, someFp12);
    console.log('Fp12 squared:', fp12Squared);
}

function hexToFp12(hex: string): any {
    const c0 = bls.fields.Fp6.create({
        c0: bls.fields.Fp2.create({ c0: BigInt('0x' + hex.slice(0, 96)), c1: BigInt('0x' + hex.slice(96, 192)) }),
        c1: bls.fields.Fp2.create({ c0: BigInt('0x' + hex.slice(192, 288)), c1: BigInt('0x' + hex.slice(288, 384)) }),
        c2: bls.fields.Fp2.create({ c0: BigInt('0x' + hex.slice(384, 480)), c1: BigInt('0x' + hex.slice(480, 576)) })
    });
    const c1 = bls.fields.Fp6.create({
        c0: bls.fields.Fp2.create({ c0: BigInt('0x' + hex.slice(576, 672)), c1: BigInt('0x' + hex.slice(672, 768)) }),
        c1: bls.fields.Fp2.create({ c0: BigInt('0x' + hex.slice(768, 864)), c1: BigInt('0x' + hex.slice(864, 960)) }),
        c2: bls.fields.Fp2.create({ c0: BigInt('0x' + hex.slice(960, 1056)), c1: BigInt('0x' + hex.slice(1056, 1152)) })
    });
    return bls.fields.Fp12.create({ c0, c1 });
}

function convertToCyclotomic(fp12: any): any {
    const p = BigInt('0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab'); // BLS12-381 prime
    const exponent = (p ** BigInt(4)) - (p ** BigInt(2)) + BigInt(1);
    return bls.fields.Fp12.pow(fp12, exponent);
}

function fp12ToHex(fp12: any): string {
    const c0 = fp12.c0;
    const c1 = fp12.c1;
    return [
        bigintToBigEndianHex(c0.c0.c0, 48), bigintToBigEndianHex(c0.c0.c1, 48),
        bigintToBigEndianHex(c0.c1.c0, 48), bigintToBigEndianHex(c0.c1.c1, 48),
        bigintToBigEndianHex(c0.c2.c0, 48), bigintToBigEndianHex(c0.c2.c1, 48),
        bigintToBigEndianHex(c1.c0.c0, 48), bigintToBigEndianHex(c1.c0.c1, 48),
        bigintToBigEndianHex(c1.c1.c0, 48), bigintToBigEndianHex(c1.c1.c1, 48),
        bigintToBigEndianHex(c1.c2.c0, 48), bigintToBigEndianHex(c1.c2.c1, 48)
    ].join('');
}

const testCrypt = () => {
    // Example usage
    const kzg = "050000000000000097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb895c9094c4b01734283e744461c0a35630f5a8f5a7b1f413abc6a22f0403fd1ee7e4aa816762d2b27ffc1555fbefd4a0973bfa8d77bd5df4b8c29c3503b0468a28e25f4676ff069c3af1ef3af6ccf708aeeab4fc217c50c5fcd180730e97994282eed87d3835c0dda5b4c717014f276cf2eec5023eeaec51ec240afd862e6ded0bb0559f25863774ea38754556deb4fea2846f21f2083940ae18febfe5bb6cd012ea440add83153787b83af979026b49929d3febea6caa64f652cac68eaddb12050000000000000093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8b40748a77a5859e873d43ceb66a5a7cbb55aed02bc100a0286f8fa1b434d99e10c749087a8bc838191eb7202e0e7051715b08f4ac6df9e7f9fd2aae9c53a81adf6fc8cacf86a3d814312967280da5e875a6c825936e7c17d8081e1216f31faf3936ef55385bd7e909393bd4e8b030253a66aacceb3b359ab9ba095242bb4596b7425cf091399eedbc908731900c008090914ddf5708fafb608e0ec75edb52260725e53768e8b564b94180ad8b0abfe355220c69ada5dad7824b30e5ed0df8bac822241eb5b4631246dea24ae9396f6667970eb6da7d450b4659584a95e4458b26a41c7f54985cab64454e3a38b80c5890f31b3b00092cce4053976867e465590ceff07cc9319e3c515ce2c6e876c2893c71d917094a70c6f767c7f4384f078ab8efa3e2d1a57c1907db0117084deac0413dc22ff4d34b0253daeefc440dcfd4823333792a4e78510b0709f7c02bbbbdf0ee73e994216e2be3d1bb0909e1ac2c68f6116f618f0df72e4fb6442793cd8351653611a1e4728aeedc49a0b02a5bca3";
    const agg_key = "0400000000000000000000000000000097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bba86a59129dabc7829ff704a76153da1526321489b4f41c1fc5b734f6eb334613faa472174f52ff0214ffa614da49a47b81b6e8025f7b89073e827fe8ae98a3dacda57ce8260951c13856f8fc86e7447c2819c3ce354b42691388d12aec3df87c0400000000000000a8849d3660df35d03e99e5c1ac14f98439901e699381d585cb0b985ec66209d4a5746836674a0bfa9c2784d4e98c4246a1543a894ff13b9ffd82060a9ebbaa23f61b69394a562a6b5f14661b3a68df1e4781188d1bde8886c5a047e50263d0efaa01cd9750d657cd81d801462ad125af638c3fba5530fa3f3aead1f353f9f80c1668450be0990dfb2c4739f80c6a61138bbbc3d80612e0548cfc7cf931ddf253d13ae15f43c6defe553b3e8bf869a2e3e1f4e2a318b456ab107c8c0357093bf0865251988b13989ac7a217619edcfe4ad70dcd1846a4c0ed43b2ef3a76bbb84d99998463b882308b83b588f5b48abc90010000000000000087c77aaf8f497a365bf9ee1fea6ccea16eda057b71f4fad0695311fc48c80eb95afa3eaced6a3ceb5340c2aed37c7c7bb0f279557368b9cd8918efcf1bc8c2683740389df78dd49f16f557e28cbe2f8f6756fdf9db972d0e7f3fab8b704d472d942a7b52948132dac7d14f63a7ce56741b03129df67e30c6a80866a84e5ac31f5b3679c50e69f8e9414c08930c41d2e9040000000000000088f0b23342b0d13e593ba48f6c5817aaa7a865a1d6959f74f3891e03ce4cf5206aacc2e7eb79a403be87d9c930f40d22aaf710862d0717bdf7a653791130e91f7f721be43942dae557962b2afbcdb4214937f50a4c9899c64c2f7f2dacbba62ba4273b2e5b71b64055e36615c3349c099282ac37035bd0581beb4bd9f33b2724e5b0c6e5222207e98ea406000da4304088db9e8ee60aff46feb0911cff1fbc259f766efe17d3f5053c43e488e8efee29aa76a74e6ad612d59f6d7e3ec091d0f18d83d6ff4fe87cf3fb1b742519560348dcdfb10b9d75d2053afa8b619c4593e69d84cc9b7f6ba32e48ded8fcb4479c7f0200000000000000a515d3b0d3c822cd2562b6657de7cc74caceae7ce70af874fa2f6f7e905d32a431274bb07d796d70628ee6cc183254b5806ddd927ce164e20b57031583ee330d486911dc248b93be40f4ed5768643e795a66c56c22264bd6c641f3c8ab5021f491b51d2454f728173b826f26a4bf0f50c2f29a1f3b9924345019a1baf702df5b18ab0753c5e4021ac8e0ee1de54c3ae00400000000000000a23788d9822d745a70c3288c50f9c5612453ed6c1bc489c0693954dce1ebeb763c942ff80428df21cf80d1fc3f14144d995f5d03c1a96e07f70c1572d39e5e38ff3adb492ba7fb980e63ba882921022bbb33a8d243407a8e0c2845c483decd4fb265f750abbb2febfad920a5f1d40e5aa80ddc62a5fc4568120104c7e7da662cac4ba3bb4ee07b17d61bee08d7192c7e98a0a290098d9ed67557b7fb961f4b3886238c7cc351979caf8930e968cd488a4c9d9f72990d8fc54ae3b3acb5f0744fb755af91bee1c8656d748d75234bac6ee01fbaeff7e18df093f3f90e1dfac2b6990e7759f2cbb577832acaa0a76816200300000000000000b9f884b889858ca1dba3ff73d5d9fa7beb69aa7af103a65d60d50b4e1f87b9cbc150e2660b83062aa7714210467fe7e0b6772dbb8a04191975f5cb6867dc2345d6e7446fe157f97fc55776bb2d8b53564599e447fc0ac51c658b4b38feaf8c3d869face60eda29cff6f2502b1cfa6cf4678f4e6b4821dc5ce30a57a81b72e64d2d68af8d80524ce49345b69b211ef7b20400000000000000a565afbb71752806b504426fb4401c5dff72eb37c067385bb05ad3498266983b2cefe57edccebd4e2be31933dadb1995a066641ba7d47a6e20ba9b7767dc4784457eecbcd8cdb29a60b420e241da9577d40e8528777aaf3fb0889789408a08f188de9056d8667f76600f96eabce4540aacf6518720b716ada453ba92448da8a5e57eee35a59e000a6b196c5bf41a94fd89efb1dbba323130bbb4b8646bd3acee3ff46f48b8ffabde6585c0a56426a08450499929d9fa3ecb387ebbe565a1bf92a1f43384991d324b9d48416ec2b3829ae9cc15bdc1c1f16c6d62265e40bd0c67df5a26e668406655ac91ade175969fd40400000000000000afadc6124fdf930dc6ed5c96c703a4c7c9d5210e486c1e7f5510e45969d4ab9f1d121ddc641579c5fe050860ce87415bb6b2b84bed7ff640b41d543d1b7b3832f7d16c79e28cb46425dc1dfab7ae99396a2f6f78ce315ef59081e5df2eee2f7192e0f4adcebb23054a8f0088991e7a47bee85133ae20acdafaaa2d9fe6c7958c81cf89478cbc5dce5b0c0c266f86ac68ab6c242eb6ec53ab425471f4bd97c64d4b6784e3df2c08cc7068b0f4de08006cf4b1c218eabe696b1ca51a786ec64b09b80bc8ee36d2b25ad1738b94e2874271543cba19c722a657612b893547418005caa72934cbe523bff9adbbfaeeecdccb9900478282abc351dbd0aebab8b7d5616490e522ec4df828bf161a1546a647ed58c4b2a765a96035bee6a2ee1be76c080a02bb63a6a83f4f03acf8a3406934ffc4b9e2b5a35ff52eb1ed007967740e239f3377fd81753c175f84ab6407f983b7b3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8b68917caaa0543a808c53908f694d1b6e7b38de90ce9d83d505ca1ef1b442d2727d7d06831d8b2a7920afc71d8eb50120f17a0ea982a88591d9f43503e94a8f1abaf2e4589f65aafb7923c484540a868883432a5c60e75860b11e5465b1c9a08873ec29e844c1c888cb396933057ffdd541b03a5220eda16b2b3a6728ea678034ce39c6839f20397202d7c5c44bb68134f93193cec215031b17399577a1de5ff1f5b0666bdd8907c61a7651e4e79e0372951505a07fa73c25788db6eb8023519a5aa97b51f1cad1d43d8aabbff4dc319c79a58cafc035218747c2f75daf8f2fb7c00c44da85b129113173d4722f5b201b6b4454062e9ea8ba78c5ca3cadaf7238b47bace5ce561804ae16b8f4b63da4645b8457a93793cbd64a7254f150781019de87ee42682940f3e70a88683d512bb2c3fb7b2434da5dedbb2d0b3fb8487c84da0d5c315bdd69c46fb05d23763f2191aabd5d5c2e12a10b8f002ff681bfd1b2ee0bf619d80d2a795eb22f2aa7b85d5ffb671a70c94809f0dafc5b73ea2fb0657bae23373b4931bc9fa321e8848ef78894e987bff150d7d671aee30b3931ac8c50e0b3b0868effc38bf48cd24b4b811a2995ac2a09122bed9fd9fa0c510a87b10290836ad06c8203397b56a78e9a0c61c77e56ccb4f1bc3d3fcaea7550f3503efe30f2d24f00891cb45620605fcfaa4292687b3a7db7c1c0554a93579e889a121fd8f72649b2402996a084d2381c5043166673b3849e4fd1e7ee4af24aa8ed443f56dfd6b68ffde4435a92cd7a4ac3bc77e1ad0cb728606cf08bf6386e5410f";
    const powersOfTau = decodePowersOfTau(kzg);
    const aggregateKey = decodeAggregateKey(agg_key);

    console.log(powersOfTau, aggregateKey);
    const ciph = encrypt(powersOfTau, aggregateKey, 2);
    console.log(ciph);
    const encoded = encodeCiphertext(ciph);
    console.log(encoded);
}

demoFieldOperations();

function bigintToBigEndianHex(value: BigInt, length: number): string {
    // Convert BigInt to hex string without the '0x' prefix
    let hex = value.toString(16);
    
    // Ensure the hex string is padded to the desired length
    if (hex.length > length * 2) {
        throw new Error('BigInt value is too large to fit in the specified length');
    }
    
    // Pad the hex string with leading zeros
    hex = hex.padStart(length * 2, '0');
    
    // Convert the hex string to a byte array
    const byteArray = hex.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || [];
    
    // Reverse the byte array to get big-endian format
    const reversedByteArray = byteArray.reverse();
    
    // Convert the reversed byte array back to a hex string
    const bigEndianHex = reversedByteArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    
    return bigEndianHex;
}

export { decodeAggregateKey, decodePowersOfTau, encodeCiphertext, encrypt, testCrypt };