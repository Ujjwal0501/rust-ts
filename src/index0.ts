// import { CurveType } from '@noble/curves/abstract/bls';
import { bls12_381 as bls } from '@noble/curves/bls12-381';
import { Buffer } from 'buffer';
import { ProjPointType } from '@noble/curves/abstract/weierstrass';
import { Fp, Fp12, Fp2, } from '@noble/curves/abstract/tower';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha256';

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
    const gamma = bls.fields.Fr.create(BigInt('0x' + reverseEndianess('8660d3c2a2ab458dd6da04d3e7cb5cf6edb702dfa2fa0c952cd6f3bcdc0fdb1a')));
    console.log(gamma.toString(16));
    // const gamma = bls.G1.normPrivateKeyToScalar(bls.utils.randomPrivateKey());
    const gamma_g2 = params.powers_of_h[0].multiply(gamma);
    console.log(gamma_g2.toHex(true));

    let g = params.powers_of_g[0];
    let h = params.powers_of_h[0];

    let sa1 = [bls.G1.ProjectivePoint.BASE, bls.G1.ProjectivePoint.BASE];
    let sa2: ProjPointType<Fp2>[] = Array(6).fill(bls.G2.ProjectivePoint.BASE);
    sa1.forEach((value, index) => {
        console.log(`sa1[${index}]: ${value.toHex(true)}`);
    });
    sa2.forEach((value, index) => {
        console.log(`sa2[${index}]: ${value.toHex(true)}`);
    });

    const hexValues = [
        reverseEndianess('08ca6f2a35f8f6f9cad58e9d764d450af154c246fc04266151e2a5493ff02943'),
        reverseEndianess('8696a66087578b92e1b4b11c6b4c06d4694a9bed1f9468f0115e7f2648eb021d'),
        reverseEndianess('91e201cc83dc03cc47d63cfb8a9016e73ffd1a78fffd14e4dfcdf2cbb9a7245d'),
        reverseEndianess('a90598c6e0f25c3a104fc94632b1d58cf21bca3bbd7e41da07feb9c14e0fa60d'),
        reverseEndianess('d3f5a9fc8abfef02fb6095c08ba4f3445b36f0fb963579bc5112d34a02044567')
    ];

    let s = hexValues.map(hex => bls.G1.normPrivateKeyToScalar(hex));
    s.forEach((value, index) => {
        console.log(`s[${index}]: ${value.toString(16)}`);
    });
    // const s = Array.from({ length: 5 }, () => bls.G1.normPrivateKeyToScalar(bls.utils.randomPrivateKey()));

    // sa1[0] = s0*ask + s3*g^{tau^t} + s4*g
    sa1[0] = apk.ask.multiply(s[0])
        .add(params.powers_of_g[t].multiply(s[3]))
        .add(params.powers_of_g[0].multiply(s[4]));

    // sa1[1] = s2*g
    sa1[1] = g.multiply(s[2]);

    // sa2[0] = s0*h + s2*gamma_g2
    sa2[0] = h.multiply(s[0])
        .add(gamma_g2.multiply(s[2]));

    // sa2[1] = s0*z_g2
    sa2[1] = apk.z_g2.multiply(s[0]);

    // sa2[2] = s0*h^tau + s1*h^tau
    sa2[2] = params.powers_of_h[1].multiply(s[0])
        .add(params.powers_of_h[1].multiply(s[1]));

    // sa2[3] = s1*h
    sa2[3] = h.multiply(s[1]);

    // sa2[4] = s3*h
    sa2[4] = h.multiply(s[3]);

    // sa2[5] = s4*h^{tau - omega^0}
    sa2[5] = params.powers_of_h[1]
        .add(apk.h_minus1)
        .multiply(s[4]);

    // enc_key = s4*e_gh
    const enc_key = bls.fields.Fp12.pow(apk.e_gh, s[4]);
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
            const point = BigInt('0x' + pointBuffer.reverse().toString('hex'));
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

    const gamma_g2Buffer = writeProjPointTypeFp2(input.gamma_g2);
    const sa1Buffer = Buffer.concat(input.sa1.map(writeProjPointTypeFp));
    const sa2Buffer = Buffer.concat(input.sa2.map(writeProjPointTypeFp2));
    const enc_keyBuffer = Buffer.from(fp12ToHex(input.enc_key), 'hex');
    const tBuffer = Buffer.alloc(8);
    tBuffer.writeBigUInt64LE(BigInt(input.t), 0);

    const totalLength = gamma_g2Buffer.length + sa1Buffer.length + sa2Buffer.length + enc_keyBuffer.length + tBuffer.length;

    const resultBuffer = Buffer.concat([gamma_g2Buffer, sa1Buffer, sa2Buffer, enc_keyBuffer, tBuffer], totalLength);
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

    const scalar = bls.fields.Fr.create(BigInt('0x1d8a77a2bc0faf4c4c904eed119108ed9b375265f7d06cec6862a2a97c3adb27'));
    console.log('Scalar: ', scalar.toString(16));

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
    const g1_scalar_mul = g1_a.multiply(scalar);
    console.log('G1 a + b: ', g1_sum.toHex(true));
    console.log('G1 a - b: ', g1_sub.toHex(true));
    console.log('G1 -a: ', g1_neg.toHex(true));
    console.log('G1 2a: ', g1_dbl.toHex(true));
    console.log('G1 scalar mul: ', g1_scalar_mul.toHex(true));

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
    const g2_scalar_mul = g2_a.multiply(scalar);
    console.log('G2 a + b: ', g2_sum.toHex(true));
    console.log('G2 a - b: ', g2_sub.toHex(true));
    console.log('G2 -a: ', g2_neg.toHex(true));
    console.log('G2 2a: ', g2_dbl.toHex(true));
    console.log('G2 scalar mul: ', g2_scalar_mul.toHex(true));

    // Create an Fp12 element and do squaring
    const fp12_a = hexToFp12('7b41018107fbe009aeb2ae912921bb2145b658bff588daea81a2d53a8c4aee171935fcc96fb395398ae4e4b20d937e16967f5e6a543f14a6751a869bfd22c8d96857389065eb86aa6784483efafc422ddb530f3dd76b3ce620605f6e21ee8c13f0a6b6f84a6ab78fdc1167e447c4f3a1d7cc51cf686646b7b31199d3e453c009ca949eb79696bf3d64c68a92e66fcc1514605dea849d01626006d806aca856a641993f84d2c620e6c97f4d8773c7664baee35761c576f687d6a643c3c6257b07f1f07ec6b0eb29ebaa9cb4088b29db25d2612fa604c96b3d148f0f8a954a0777b6e21f4b51f69530401651d1d0c9480ff23d5c0c0d34ede48be9c08dd6bbee77015deddac23d10eebd64ff1ecbce86a696f051fabe6c26e15e3b946afcc2b613f0b3a2126b6533792284bc5fc90a899c4c3a05b2491ce6903a9b2d85f30d630f421324492cbbbaf174cdc1a29adc110bb4891940fa9e8ad79520296819a6b6a32a578f7283c44d9c45e0c2676e0bbb4522cbdc23baebfa3cb008f43700a67207d7eb10a9d82cc576cbe3e10bac5e23613d456c18a512180869f48b52117c8dd1de9ce4728737d3239cfe829ccea8740e42c737ff961d5cff8d9ca0da3434ed909a3d362411cdb5c8e1bc917913c3cd783c3974621309d255f81c06e46132e0076209171b0ffea3ed0541e03d78856c018912927c520c56af071062972d1cb07276d8dcea9746000dbca97f78060e1815d22f5f88652aa53ae1664e449457c2e700e65efdaff38ac0a7849f4966411153dfd1befa7bab0d1889cc643e82809911');
    const fp12_b = hexToFp12('d9b0619e9e724685d2eb06d509523870f9dfe07c7d7fb623632fc8f3ef8acd66fd9ed31a79af676ac1c2adc48ff018066f12bda4c5b225652d002ccba86315d57ebf098d35f3987a0b79f4d989c09c0c6373e58ac42c24e5a3b16d3eafa3e91020f0bfea83f3f1736732e71aac76e40399ec881a62a93426306be1e9dfc6645f1649a1d26d7d1ada5aca07c57551250749995a15db818c0aa7acb4606e7f41b65375308abbd547f7b8d90f10e1a7bfba60924a451108c8b896efa7355e14af10c096bb64e70e0c055e27e79b3b7552aa0b36bd3eace4759e13a31eabaea322bf978d2815b287e7c4d31281c85898090b57af368ceefe8be408504a0d57c542ad8e73f44211df17c89a2fd099f25895615828c884d9c31e514819d63856841601cce68807457db323e23db4bbc9a80900fb19aafd655069700db1b5d5a5753adedab2bd556fdc1774a54f0733a51e3c18f16e700f87ade824f35dde86023a5b7d816031e0eac3c4d82a80637a777969815fbd3ddcfcaf77ed7d9ad7c8c886530414d76c34808efefd57b488b065319f573a4ac806eb5da273c4320301ca6de6c682cd844f0a08c9b5e86f29431c32830d1feedf4d8bcd5d5ca90ef15084fffb98abe683d36e9de474ed069e8f72f4cdc7043cd38cb59878acef0674d0b48b8f0b9a0df326c8c7e97a5f35dcc1377f2e68d2e6076afb792db5ad38cb01158571e0c8b644e77c8d1b574653dcd73941070cd34deac7afe916952d3b67b4ad3e8993b33308c282de58e37afb28ae2afbb44f8e56b2e3ef575b67c5bc3112ccfedd07');
    const fp12_zero = bls.fields.Fp12.ZERO;
    const fp12_one = bls.fields.Fp12.ONE;
    const fp12_pairing = bls.pairing(g1_a, g2_b);
    const fp12_scalar_mul = bls.fields.Fp12.pow(fp12_pairing, scalar);

    console.log('Fp12 a:', fp12ToHex(fp12_a));
    console.log('Fp12 b:', fp12ToHex(fp12_b));
    console.log('Fp12 zero:', fp12ToHex(fp12_zero));
    console.log('Fp12 one:', fp12ToHex(fp12_one));
    console.log('Fp12 pairing:', fp12ToHex(fp12_pairing));
    console.log('Fp12 scalar mul:', fp12ToHex(fp12_scalar_mul));

    const fp12_add = bls.fields.Fp12.add(fp12_a, fp12_b);
    const fp12_sub = bls.fields.Fp12.sub(fp12_a, fp12_b);
    const fp12_neg = bls.fields.Fp12.neg(fp12_a);
    const fp12_mul = bls.fields.Fp12.mul(fp12_a, fp12_b);
    const fp12_inv = bls.fields.Fp12.inv(fp12_a);

    console.log('Fp12 add:', fp12ToHex(fp12_add));
    console.log('Fp12 sub:', fp12ToHex(fp12_sub));
    console.log('Fp12 neg:', fp12ToHex(fp12_neg));
    console.log('Fp12 mul:', fp12ToHex(fp12_mul));
    console.log('Fp12 inv:', fp12ToHex(fp12_inv));
}

function hexToFp12(hex: string): any {
    const c0 = bls.fields.Fp6.create({
        c0: bls.fields.Fp2.create({ c0: BigInt('0x' + reverseEndianess(hex.slice(0, 96))), c1: BigInt('0x' + reverseEndianess(hex.slice(96, 192))) }),
        c1: bls.fields.Fp2.create({ c0: BigInt('0x' + reverseEndianess(hex.slice(192, 288))), c1: BigInt('0x' + reverseEndianess(hex.slice(288, 384))) }),
        c2: bls.fields.Fp2.create({ c0: BigInt('0x' + reverseEndianess(hex.slice(384, 480))), c1: BigInt('0x' + reverseEndianess(hex.slice(480, 576))) })
    });
    const c1 = bls.fields.Fp6.create({
        c0: bls.fields.Fp2.create({ c0: BigInt('0x' + reverseEndianess(hex.slice(576, 672))), c1: BigInt('0x' + reverseEndianess(hex.slice(672, 768))) }),
        c1: bls.fields.Fp2.create({ c0: BigInt('0x' + reverseEndianess(hex.slice(768, 864))), c1: BigInt('0x' + reverseEndianess(hex.slice(864, 960))) }),
        c2: bls.fields.Fp2.create({ c0: BigInt('0x' + reverseEndianess(hex.slice(960, 1056))), c1: BigInt('0x' + reverseEndianess(hex.slice(1056, 1152))) })
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
    const kzg = "050000000000000097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bba66faaac40fdee8c3c1d45504ef7de2ea2e70116c840e890663db1ff806b637e9e09aadf107b12eec69e17a195dea013a3611a4fe72b1b9a992b7ceab4030c25700354febd090032297468c4df5401c633b1b37cfbf60d695730e2099f32c4cd8bd8b289e42e9b22e31c20f4f603983901c6b83bd7e45347f15d229f9551c700e728c6aba6eeaf6114991ac3ba824a7ba91a07fa1966c955253f068ad5e631c6eccea80444865eb5936c73d4dadba2195ead003be3b5959bb734bc9d709c3db1050000000000000093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8a484e6165080bbe30da99214ae7732c054628f7101388540ecb3a3cbf458124c173914e6d4798e089e5a1f897d8f3336001b101dd444ea602016f8a54770703439927a08d376d27efb3048692afc2ca35881c0fb0738b259afbd9cfb6ae6b9348bfd6e0c50557f1f6ea82958f017c807d040b6dee615687b0c80740ea1310dfca8ddda48e6ae96e65a2b1003ef2e9c560dfe4533bcf76074224e1b28c34de3ded2f4716faf488af6e29845340b58bbbcff493c9ec78fa12882210571b8bdecb4b8a0822ae9a4a038e8f7197f77e1be3ae87b6aabf1db7e7ae47bd284bd191dd29765589ad5edfed028743d7bf215debe17293ce739d0b93ffc5c29cc7eff57d42d8b9e3568f94d3da89d7901260c7f96c1513c31e7df617b6f12e60556820d10a98ceb629ccc67ee871ddc1387cf2164c2364605fc23ce175959ab259b17a815fd22ff78922bfa928abdb4fa8e48e629015d800ee5d79220d097aafce2de319922c50f304a3ae880b054e7864a94406f99d1c7a90c8f582ac04d70c0e8cac8b0";
    const agg_key = "0400000000000000000000000000000097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb985ccc4d04856dae505a2d2389fc01ef5516161a76e9ea93373f0f9494b52d13914099e3d435ef48ca25b6b61c1d1330a6277c4320791a87964f70f233073d56cac7a9ccbf7df2d4b1d5913310ad5cbd522ec789533ab225bae9d95b44d7fe970400000000000000838a186a26bcd9b712201284a4911b845c9eafe33a9ec215d6ac727ad3165eb037cdb061bffbf739493de50627cf075bad1add79b7b1385afde4c00a11894204280e073534b8a24ffdf8ef4ff6f6b02e049e1bbe87704ddeefbf3bae686b4eb48f14bf2802e5e4041e290817313d35add8acbce644dbac2cdc811d98a5d6f45b50461f7224c0e1eeb3c6a0752d114424977ca485a82ae33dcd6cb19ae6f2c972e08612380c2d1c165eba244e3036ddbf20b6987558339c27f293fe12e06bae56a2db1d8ccfb2e03d6e64b297f7ae9e66ac8a9c7723290081fc01fe8010ff10bca90ad4ce97ac1c17d0e3603dd112a9800100000000000000970010e5b9cc5a2e49a45c676b6d444af3d4da21c7352c8b285879c88b6039b83d845dae093f01a38ada297bb1bf23b0a9dc90a731445fc74556ae31d5cffc7d75e07ec1a6802b03f59d689f5ee40bae25e9252ccf3b80185eb32944e0879e45a45dd74adc58121c5a627cf334e53363108bc3ab5b575d1c6b8c002773ddabb86810abc9c2982ce19bc5a263cd83e19304000000000000009817395a9d1a61994e98cfccb2ad732961e65d097ce872196667ec552dc0ef5b5a1e8bd474527823017d73c1efef1eb5a80c244e3c4cc85160fd2ad2826743e35457473868c2e8bfb929eeb1357ddc691b24cbfb8547658c39c7762d6d36eedb92cd44b2fb19f77be91b3e45123fe5ed5184050d819861ec14cf6e28520100412e52d80fc15dd4a0cae3a2933b208963a7eaf8d1c4b677ff972bc04b3db8a0c643d8eb355017cc91299bd0ffbe88184d7e6790e35c6ce3d80ac5318053530706988083839e85b62d46514f8b7a9749960aa3cfbe4af333b66528670e577239dbb525d16a953e6375f4343625a23ae690020000000000000094f6e52fffd19e600b190177eda8401cea253531db41d99b3615cf6658f3a18fa8a0c0d635b6dbba6abfb1fea5a0a5ed8f1e0ff3bf1b59115b716a75c95811d29bb0a1da27b7e0ebaf38e441b3ec50ef4685a04bdcaf132d6e8854eaf44070f3b15f069d14984ec06d92ea2d887ab530c7d47d98362de6f001b5428e6bdfa3398858583a701bc467aad3aedecbfacc830400000000000000b706eec9c74d3bf1512a8ba400c9dbbdd1cd19be7f70d0b1ce9ddd85189eed4b3a042a095bf069682f6a69c3cca655b18ada11fea183bbddce5acda53b4689f8e820eeebbea7dc6e30e99b36930146b3dfbfda689cd4cb8c3e18cef6ed40b0ae80ba14c1ae752eb9cade78ccb6427f973afe5088b4e0c667602b8f09e0e8779ac06f49da7fcab83dafc2b1464143346fb18969e308ba1f3c5b1b5bc1e09e9309e13109650aa9503cdd2dc7c74964c80469e29c25cf075abf86dbcb943d8bdb0b9938a0d432a47d1e8ae8c496bc62b7f95cdb2d7124d56a98557c1af05a147b266f185c0a1eb3b0048f036f46c7a2de600300000000000000b951b5683430b5201b861e46581904119e1e5bf9c8c596c84ddc3e0d08aeb0e00f5a52c84f265edc7277e8677a3fb98cb93a2802403358e8ed2f7bf1fe4188cadb0fb80c3bd83544d1458dc95861f516cebefd1c70e555adb8f5e57478867b908a3577febc5839b8fdc5ae9bc8d4398a94ef9ee5da571b28cec5ba2b80daaac7ea3e267c053a9dde1f8e039ca4453906040000000000000099522b4d6264167ae678cea8e4c9ff2d196408f15e922341933fa21a30ce2a9e51369e141951dd2defdb27400d1c5f26953db9595e4baa87f68d537f7f390de997ea06bafcbd8f941ad4546884ea2a2fc4900f972ef21983d2d22be9e8844c5da9c5b5548a4904a69f82d0b7df7ce5dbc370602d98299b5e7482d5032a33e111ebed5b861b502fbc9cca1606f0fdb874b7da820d1af9609a930568b6851911fdb9c5b31894ad9a3c8861bdb64362439eaf90b35f2cb88a3adc47f8bd7fc2a8ef99bc3586c2aad0ef562247186c14d70bbd503064b97143d942b16242fdf1989069abaafdc748f15299582ffb61bb3caa04000000000000008b3272366394f554e778c9a0fc59c86e06dab272137c63e5e16667c021dfd36b0f0e395cc7e5f911d66e546c5923f009a491e18cbe682595b0692ad229de9a391e16019e94c6ea5bf162c8e9964eebdc206bda11a445abda726adaf8ed960eacb1b18cd0eb4345e404e9d0b79d17b1c366f153aec3ef8c9d1b8485af4503ea83adc9b4d22b5c2de0ebfabe74add65b428cf0893484f9efa75ee69e250a360d79bbef91a162d57e3584ca7019fa9a2940cf4bfa8bbb271f652891974aa331fd43a6eb7bfc5afd2cbc6c81e08e978d17347582217bb919912defba82fe3e463215b437fb0e0304e465a3917d5433a76591973f601205285a96e58e482efbbe70682b79f54173319e06decb3282d6986178937eeba8db2a60056ed3921f48c65f4e0aded64b3052bc39aa1a3e3f67347750735fd52b94e644d54c60fa754acdbffdc4e72a3205ae3958d7bfc1be6d33928db3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8b68917caaa0543a808c53908f694d1b6e7b38de90ce9d83d505ca1ef1b442d2727d7d06831d8b2a7920afc71d8eb50120f17a0ea982a88591d9f43503e94a8f1abaf2e4589f65aafb7923c484540a868883432a5c60e75860b11e5465b1c9a08873ec29e844c1c888cb396933057ffdd541b03a5220eda16b2b3a6728ea678034ce39c6839f20397202d7c5c44bb68134f93193cec215031b17399577a1de5ff1f5b0666bdd8907c61a7651e4e79e0372951505a07fa73c25788db6eb8023519a5aa97b51f1cad1d43d8aabbff4dc319c79a58cafc035218747c2f75daf8f2fb7c00c44da85b129113173d4722f5b201b6b4454062e9ea8ba78c5ca3cadaf7238b47bace5ce561804ae16b8f4b63da4645b8457a93793cbd64a7254f150781019de87ee42682940f3e70a88683d512bb2c3fb7b2434da5dedbb2d0b3fb8487c84da0d5c315bdd69c46fb05d23763f2191aabd5d5c2e12a10b8f002ff681bfd1b2ee0bf619d80d2a795eb22f2aa7b85d5ffb671a70c94809f0dafc5b73ea2fb0657bae23373b4931bc9fa321e8848ef78894e987bff150d7d671aee30b3931ac8c50e0b3b0868effc38bf48cd24b4b811a2995ac2a09122bed9fd9fa0c510a87b10290836ad06c8203397b56a78e9a0c61c77e56ccb4f1bc3d3fcaea7550f3503efe30f2d24f00891cb45620605fcfaa4292687b3a7db7c1c0554a93579e889a121fd8f72649b2402996a084d2381c5043166673b3849e4fd1e7ee4af24aa8ed443f56dfd6b68ffde4435a92cd7a4ac3bc77e1ad0cb728606cf08bf6386e5410f";
    const powersOfTau = decodePowersOfTau(kzg);
    const aggregateKey = decodeAggregateKey(agg_key);

    console.log(powersOfTau, aggregateKey);
    const ciph = encrypt(powersOfTau, aggregateKey, 2);
    console.log(ciph);
    const encoded = encodeCiphertext(ciph);
    console.log(encoded);
}

/**
 * Performs key stretching using HKDF with SHA-256.
 *
 * @param input - The input hex string.
 * @returns A stretched key as a hex string.
 */
function keyStretching(input: string): string {
    const inputBuffer = Buffer.from(input, 'hex');
    const salt = new Uint8Array(32); // 32 bytes of zero
    const info = new TextEncoder().encode('aes_encryption');
    const stretchedKey = hkdf(sha256, inputBuffer, salt, info, 32); // 32 bytes output key length
    return Buffer.from(stretchedKey).toString('hex');
}

demoFieldOperations();
testCrypt();

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

function reverseEndianess(hex: string): string {
    // Ensure the hex string has an even length
    if (hex.length % 2 !== 0) {
        throw new Error('Hex string must have an even length');
    }

    // Split the hex string into an array of bytes
    const byteArray = hex.match(/.{1,2}/g) || [];

    // Reverse the array of bytes
    const reversedByteArray = byteArray.reverse();

    // Join the reversed array back into a hex string
    return reversedByteArray.join('');
}

export { decodeAggregateKey, decodePowersOfTau, encodeCiphertext, encrypt, testCrypt };