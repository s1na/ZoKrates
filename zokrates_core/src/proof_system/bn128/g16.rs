use crate::ir;
use crate::proof_system::bn128::utils::bellman::Computation;
use crate::proof_system::bn128::utils::solidity::{SOLIDITY_G2_ADDITION_LIB, SOLIDITY_PAIRING_LIB};
use crate::proof_system::ProofSystem;
use bellman::groth16::Parameters;
use regex::Regex;
use std::fs::File;
#[cfg(feature = "scout")]
use std::io::Read;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use zokrates_field::field::FieldPrime;

const G16_WARNING: &str = "WARNING: You are using the G16 scheme which is subject to malleability. See zokrates.github.io/reference/proving_schemes.html#g16-malleability for implications.";

pub struct G16 {}
impl ProofSystem for G16 {
    fn setup(&self, program: ir::Prog<FieldPrime>, pk_path: &str, vk_path: &str) {
        std::env::set_var("BELLMAN_VERBOSE", "0");

        println!("{}", G16_WARNING);

        let parameters = Computation::without_witness(program).setup();
        let parameters_file = File::create(PathBuf::from(pk_path)).unwrap();
        parameters.write(parameters_file).unwrap();
        let mut vk_file = File::create(PathBuf::from(vk_path)).unwrap();
        vk_file
            .write(serialize::serialize_vk(parameters.vk).as_ref())
            .unwrap();
    }

    fn generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        pk_path: &str,
        proof_path: &str,
    ) -> bool {
        std::env::set_var("BELLMAN_VERBOSE", "0");

        println!("{}", G16_WARNING);

        let computation = Computation::with_witness(program, witness);
        let parameters_file = File::open(PathBuf::from(pk_path)).unwrap();

        let params = Parameters::read(parameters_file, true).unwrap();

        let proof = computation.clone().prove(&params);

        let mut proof_file = File::create(PathBuf::from(proof_path)).unwrap();
        write!(
            proof_file,
            "{}",
            serialize::serialize_proof(&proof, &computation.public_inputs_values())
        )
        .unwrap();
        true
    }

    fn export_solidity_verifier(&self, reader: BufReader<File>) -> String {
        let mut lines = reader.lines();

        let mut template_text = String::from(CONTRACT_TEMPLATE);
        let gamma_abc_template = String::from("vk.gammaABC[index] = Pairing.G1Point(points);"); //copy this for each entry

        //replace things in template
        let vk_regex = Regex::new(r#"(<%vk_[^i%]*%>)"#).unwrap();
        let vk_gamma_abc_len_regex = Regex::new(r#"(<%vk_gammaABC_length%>)"#).unwrap();
        let vk_gamma_abc_index_regex = Regex::new(r#"index"#).unwrap();
        let vk_gamma_abc_points_regex = Regex::new(r#"points"#).unwrap();
        let vk_gamma_abc_repeat_regex = Regex::new(r#"(<%vk_gammaABC_pts%>)"#).unwrap();
        let vk_input_len_regex = Regex::new(r#"(<%vk_input_length%>)"#).unwrap();

        for _ in 0..4 {
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            template_text = vk_regex
                .replace(template_text.as_str(), current_line_split[1].trim())
                .into_owned();
        }

        let current_line: String = lines
            .next()
            .expect("Unexpected end of file in verification key!")
            .unwrap();
        let current_line_split: Vec<&str> = current_line.split("=").collect();
        assert_eq!(current_line_split.len(), 2);
        let gamma_abc_count: i32 = current_line_split[1].trim().parse().unwrap();

        template_text = vk_gamma_abc_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count).as_str(),
            )
            .into_owned();
        template_text = vk_input_len_regex
            .replace(
                template_text.as_str(),
                format!("{}", gamma_abc_count - 1).as_str(),
            )
            .into_owned();

        let mut gamma_abc_repeat_text = String::new();
        for x in 0..gamma_abc_count {
            let mut curr_template = gamma_abc_template.clone();
            let current_line: String = lines
                .next()
                .expect("Unexpected end of file in verification key!")
                .unwrap();
            let current_line_split: Vec<&str> = current_line.split("=").collect();
            assert_eq!(current_line_split.len(), 2);
            curr_template = vk_gamma_abc_index_regex
                .replace(curr_template.as_str(), format!("{}", x).as_str())
                .into_owned();
            curr_template = vk_gamma_abc_points_regex
                .replace(curr_template.as_str(), current_line_split[1].trim())
                .into_owned();
            gamma_abc_repeat_text.push_str(curr_template.as_str());
            if x < gamma_abc_count - 1 {
                gamma_abc_repeat_text.push_str("\n        ");
            }
        }
        template_text = vk_gamma_abc_repeat_regex
            .replace(template_text.as_str(), gamma_abc_repeat_text.as_str())
            .into_owned();

        let re = Regex::new(r"(?P<v>0[xX][0-9a-fA-F]{64})").unwrap();
        template_text = re.replace_all(&template_text, "uint256($v)").to_string();

        format!(
            "{}{}{}",
            SOLIDITY_G2_ADDITION_LIB, SOLIDITY_PAIRING_LIB, template_text
        )
    }

    #[cfg(feature = "scout")]
    fn scout_generate_proof(
        &self,
        program: ir::Prog<FieldPrime>,
        witness: ir::Witness<FieldPrime>,
        pk_path: &str,
        proof_path: &str,
    ) -> bool {
        std::env::set_var("BELLMAN_VERBOSE", "0");

        println!("{}", G16_WARNING);

        let computation = Computation::with_witness(program, witness);
        let parameters_file = File::open(PathBuf::from(pk_path)).unwrap();

        let params = Parameters::read(parameters_file, true).unwrap();

        let proof = computation.clone().prove(&params);

        let mut proof_file = File::create(PathBuf::from(proof_path)).unwrap();
        write!(
            proof_file,
            "{}",
            serialize::serialize_scout_proof(&proof, &computation.public_inputs_values())
        )
        .unwrap();
        true
    }

    #[cfg(feature = "scout")]
    fn scout_export_verifier(&self, mut reader: BufReader<File>) -> String {
        let mut vk_raw = String::new();
        reader.read_to_string(&mut vk_raw).unwrap();

        let vk = serialize::deserialize_vk(&vk_raw);
        let mut vk_bytes = vec![];
        vk.write(&mut vk_bytes).unwrap();

        let mut template = String::from(SCOUT_VERIFIER_TEMPLATE);
        let vk_regex = Regex::new(r#"(<%vk%>)"#).unwrap();
        template = vk_regex
            .replace(template.as_str(), format!("{:?}", vk_bytes).as_str())
            .into_owned();

        format!("{}", template)
    }
}

mod serialize {

    use crate::proof_system::bn128::utils::bellman::{
        parse_fr_json, parse_g1_hex, parse_g1_json, parse_g2_hex, parse_g2_json,
    };
    use bellman::groth16::{Proof, VerifyingKey};
    use pairing::bn256::{Bn256, Fr};

    #[cfg(feature = "scout")]
    use crate::proof_system::bn128::utils::bellman::{
        decode_hex, g1_from_hex, g2_from_hex, parse_fr,
    };
    #[cfg(feature = "scout")]
    use pairing::bn256::G1Uncompressed;
    #[cfg(feature = "scout")]
    use pairing::EncodedPoint;
    #[cfg(feature = "scout")]
    use regex::Regex;

    pub fn serialize_vk(vk: VerifyingKey<Bn256>) -> String {
        format!(
            "vk.alpha = {}
    vk.beta = {}
    vk.gamma = {}
    vk.delta = {}
    vk.gammaABC.len() = {}
    {}",
            parse_g1_hex(&vk.alpha_g1),
            parse_g2_hex(&vk.beta_g2),
            parse_g2_hex(&vk.gamma_g2),
            parse_g2_hex(&vk.delta_g2),
            vk.ic.len(),
            vk.ic
                .iter()
                .enumerate()
                .map(|(i, x)| format!("vk.gammaABC[{}] = {}", i, parse_g1_hex(x)))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    pub fn serialize_proof(p: &Proof<Bn256>, inputs: &Vec<Fr>) -> String {
        format!(
            "{{
        \"proof\": {{
            \"a\": {},
            \"b\": {},
            \"c\": {}
        }},
        \"inputs\": [{}]
    }}",
            parse_g1_json(&p.a),
            parse_g2_json(&p.b),
            parse_g1_json(&p.c),
            inputs
                .iter()
                .map(parse_fr_json)
                .collect::<Vec<_>>()
                .join(", "),
        )
    }

    #[cfg(feature = "scout")]
    pub fn serialize_scout_proof(p: &Proof<Bn256>, inputs: &Vec<Fr>) -> String {
        let mut buf = vec![];

        // Write proof bytes
        p.write(&mut buf).unwrap();

        // Append number of public inputs as a u32
        buf.extend_from_slice(&(inputs.len() as u32).to_be_bytes()[..]);

        // Append each public input
        for input in inputs {
            let bytes = decode_hex(parse_fr(input).as_str());
            buf.extend(bytes);
        }

        to_hex_string(&buf)
    }

    #[cfg(feature = "scout")]
    pub fn deserialize_vk(s: &str) -> VerifyingKey<Bn256> {
        let iv_count_re = Regex::new(r"vk.gammaABC.len\(\) = (\d+)").unwrap();
        let gamma_abc_len = u32::from_str_radix(
            iv_count_re.captures(s).unwrap().get(1).unwrap().as_str(),
            10,
        )
        .unwrap();

        let alpha_re =
            Regex::new(r"vk.alpha = (0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})").unwrap();
        let a_captures = alpha_re.captures(s).unwrap();
        let alpha = g1_from_hex(
            a_captures.get(1).unwrap().as_str(),
            a_captures.get(2).unwrap().as_str(),
        );

        let beta_re = Regex::new(r"vk.beta = \[(0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})\], \[(0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})\]").unwrap();
        let b_captures = beta_re.captures(s).unwrap();
        let beta = g2_from_hex(
            b_captures.get(1).unwrap().as_str(),
            b_captures.get(2).unwrap().as_str(),
            b_captures.get(3).unwrap().as_str(),
            b_captures.get(4).unwrap().as_str(),
        );

        let gamma_re = Regex::new(r"vk.gamma = \[(0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})\], \[(0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})\]").unwrap();
        let g_captures = gamma_re.captures(s).unwrap();
        let gamma = g2_from_hex(
            g_captures.get(1).unwrap().as_str(),
            g_captures.get(2).unwrap().as_str(),
            g_captures.get(3).unwrap().as_str(),
            g_captures.get(4).unwrap().as_str(),
        );

        let delta_re = Regex::new(r"vk.delta = \[(0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})\], \[(0[xX][0-9a-fA-F]{64}), (0[xX][0-9a-fA-F]{64})\]").unwrap();
        let d_captures = delta_re.captures(s).unwrap();
        let delta = g2_from_hex(
            d_captures.get(1).unwrap().as_str(),
            d_captures.get(2).unwrap().as_str(),
            d_captures.get(3).unwrap().as_str(),
            d_captures.get(4).unwrap().as_str(),
        );

        let mut gamma_abc = vec![];
        for x in 0..gamma_abc_len {
            let gamma_abc_re = Regex::new(&format!(
                r"vk.gammaABC\[{}\] = (0[xX][0-9a-fA-F]{{64}}), (0[xX][0-9a-fA-F]{{64}})",
                x
            ))
            .unwrap();
            let ic_captures = gamma_abc_re.captures(s).unwrap();
            gamma_abc.push(g1_from_hex(
                ic_captures.get(1).unwrap().as_str(),
                ic_captures.get(2).unwrap().as_str(),
            ));
        }

        // `beta_g1` and `delta_g1` are unnecessary, set them to empty
        let empty_g1 = G1Uncompressed::empty()
            .into_affine_unchecked()
            .expect("valid affine");

        VerifyingKey {
            alpha_g1: alpha,
            beta_g1: empty_g1,
            beta_g2: beta,
            gamma_g2: gamma,
            delta_g1: empty_g1,
            delta_g2: delta,
            ic: gamma_abc,
        }
    }

    #[cfg(feature = "scout")]
    fn to_hex_string(bytes: &[u8]) -> String {
        let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        strs.connect("")
    }
}

const CONTRACT_TEMPLATE: &str = r#"
contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gammaABC;
    }
    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.a = Pairing.G1Point(<%vk_a%>);
        vk.b = Pairing.G2Point(<%vk_b%>);
        vk.gamma = Pairing.G2Point(<%vk_gamma%>);
        vk.delta = Pairing.G2Point(<%vk_delta%>);
        vk.gammaABC = new Pairing.G1Point[](<%vk_gammaABC_length%>);
        <%vk_gammaABC_pts%>
    }
    function verify(uint[] memory input, Proof memory proof) internal returns (uint) {
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gammaABC.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++)
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gammaABC[i + 1], input[i]));
        vk_x = Pairing.addition(vk_x, vk.gammaABC[0]);
        if(!Pairing.pairingProd4(
             proof.A, proof.B,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.C), vk.delta,
             Pairing.negate(vk.a), vk.b)) return 1;
        return 0;
    }
    event Verified(string s);
    function verifyTx(
            uint[2] memory a,
            uint[2][2] memory b,
            uint[2] memory c,
            uint[<%vk_input_length%>] memory input
        ) public returns (bool r) {
        Proof memory proof;
        proof.A = Pairing.G1Point(a[0], a[1]);
        proof.B = Pairing.G2Point([b[0][0], b[0][1]], [b[1][0], b[1][1]]);
        proof.C = Pairing.G1Point(c[0], c[1]);
        uint[] memory inputValues = new uint[](input.length);
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            emit Verified("Transaction successfully verified.");
            return true;
        } else {
            return false;
        }
    }
}
"#;

#[cfg(feature = "scout")]
const SCOUT_VERIFIER_TEMPLATE: &str = r#"
extern crate bellman_ce;
extern crate byteorder;
extern crate ewasm_api;
extern crate pairing_ce;
use bellman_ce::groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use byteorder::{BigEndian, ReadBytesExt};
use ewasm_api::*;
use pairing_ce::bn256::{Bn256, Fr, G1Uncompressed, G2Uncompressed};
use pairing_ce::EncodedPoint;
use std::io::Read;

extern "C" {
    fn debug_startTimer();
    fn debug_endTimer();
}

const VERIFYING_KEY: [u8; 772] = <%vk%>;

/// Copy of bellman_ce::groth16::VerifyingKey::read which uses
/// `into_affine_unchecked` instead of `into_affine` for fields
/// `beta_g1` and `delta_g1`, as they're not part of the encoded
/// verifying key and are not necessary for proof verification.
/// It also throws on any error and doesn't return a Result.
fn parse_verifying_key<R: Read>(mut reader: R) -> VerifyingKey<Bn256> {
    let mut g1_repr = G1Uncompressed::empty();
    let mut g2_repr = G2Uncompressed::empty();

    reader.read_exact(g1_repr.as_mut()).unwrap();
    let alpha_g1 = g1_repr.into_affine().unwrap();

    reader.read_exact(g1_repr.as_mut()).unwrap();
    let beta_g1 = g1_repr.into_affine_unchecked().unwrap();

    reader.read_exact(g2_repr.as_mut()).unwrap();
    let beta_g2 = g2_repr.into_affine().unwrap();

    reader.read_exact(g2_repr.as_mut()).unwrap();
    let gamma_g2 = g2_repr.into_affine().unwrap();

    reader.read_exact(g1_repr.as_mut()).unwrap();
    let delta_g1 = g1_repr.into_affine_unchecked().unwrap();

    reader.read_exact(g2_repr.as_mut()).unwrap();
    let delta_g2 = g2_repr.into_affine().unwrap();

    let ic_len = reader.read_u32::<BigEndian>().unwrap() as usize;

    let mut ic = vec![];

    for _ in 0..ic_len {
        reader.read_exact(g1_repr.as_mut()).unwrap();
        let g1 = g1_repr.into_affine().unwrap();

        ic.push(g1);
    }

    VerifyingKey {
        alpha_g1: alpha_g1,
        beta_g1: beta_g1,
        beta_g2: beta_g2,
        gamma_g2: gamma_g2,
        delta_g1: delta_g1,
        delta_g2: delta_g2,
        ic: ic,
    }
}

fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    strs.join("")
}

/// Reads encoded proof and extracts a `Proof` instance
/// along with public inputs (both in raw form and as a field element).
/// Data is encoded as following:
/// <proof: 128 byte> - <number of inputs: 4 byte> - <input 1: 32 byte> - <input 2: 32 byte>...
fn parse_proof(raw: &[u8]) -> (Proof<Bn256>, Vec<Fr>, Vec<[u8; 32]>) {
    let mut proof_raw: [u8; 128] = [0; 128];
    proof_raw[..128].copy_from_slice(&raw[..128]);
    let proof = Proof::read(&proof_raw[..]).unwrap();

    let mut inputs = vec![];
    let mut input_bytes = vec![];
    let inputs_len = u32::from_be_bytes([raw[128], raw[129], raw[130], raw[131]]);
    for i in 0..inputs_len {
        let mut input: [u8; 32] = [0; 32];
        input[..32]
            .copy_from_slice(&raw[(132 + (i * 32)) as usize..(132 + ((i + 1) * 32)) as usize]);
        input_bytes.push(input);
        let hex = to_hex_string(&input[..]);
        inputs.push(Fr::from_hex(hex.as_str()).unwrap());
    }

    (proof, inputs, input_bytes)
}

fn process_block(pre_state_root: types::Bytes32, block_data: &[u8]) -> types::Bytes32 {
    let (proof, public_inputs, public_input_bytes) = parse_proof(block_data);

    assert!(pre_state_root.bytes == public_input_bytes[0]);

    // Prepare verifying key
    let pk = parse_verifying_key(VERIFYING_KEY.as_ref());
    let pvk = prepare_verifying_key(&pk);

    // Start the benchmarking timer
    unsafe {
        debug_startTimer();
    }

    let mut post_state_root = types::Bytes32::default();
    // If proof is valid, set post_state_root to second
    // public input
    if verify_proof(&pvk, &proof, &public_inputs).unwrap() {
        post_state_root.bytes = public_input_bytes[1];
    }

    unsafe {
        debug_endTimer();
    }

    post_state_root
}

#[cfg(not(test))]
#[no_mangle]
pub extern "C" fn main() {
    assert!(eth2::block_data_size() > 0);

    let pre_state_root = eth2::load_pre_state_root();
    let block_data = eth2::acquire_block_data();
    let post_state_root = process_block(pre_state_root, &block_data);

    eth2::save_post_state_root(post_state_root)
}
"#;

#[cfg(test)]
mod tests {
    use super::*;
    mod serialize {
        use super::*;

        mod proof {
            use super::*;
            use crate::flat_absy::FlatVariable;
            use crate::ir::*;
            use crate::proof_system::bn128::g16::serialize::serialize_proof;

            #[allow(dead_code)]
            #[derive(Deserialize)]
            struct G16ProofPoints {
                a: [String; 2],
                b: [[String; 2]; 2],
                c: [String; 2],
            }

            #[allow(dead_code)]
            #[derive(Deserialize)]
            struct G16Proof {
                proof: G16ProofPoints,
                inputs: Vec<String>,
            }

            #[test]
            fn serialize() {
                let program: Prog<FieldPrime> = Prog {
                    main: Function {
                        id: String::from("main"),
                        arguments: vec![FlatVariable::new(0)],
                        returns: vec![FlatVariable::public(0)],
                        statements: vec![Statement::Constraint(
                            FlatVariable::new(0).into(),
                            FlatVariable::public(0).into(),
                        )],
                    },
                    private: vec![false],
                };

                let witness = program
                    .clone()
                    .execute::<FieldPrime>(&vec![FieldPrime::from(42)])
                    .unwrap();
                let computation = Computation::with_witness(program, witness);

                let public_inputs_values = computation.public_inputs_values();

                let params = computation.clone().setup();
                let proof = computation.prove(&params);

                let serialized_proof = serialize_proof(&proof, &public_inputs_values);
                serde_json::from_str::<G16Proof>(&serialized_proof).unwrap();
            }
        }
    }
}
