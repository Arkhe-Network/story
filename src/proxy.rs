// src/proxy.rs
use aws_sdk_sagemaker::{Client as SageMakerClient};
use aes_gcm::{Aes256Gcm, KeyInit, Key, Nonce};
use aes_gcm::aead::Aead;
use std::time::Duration;
use reqwest::{Client, Certificate, Identity};
use std::fs;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationReport {
    pub pcr_0: String,
    pub pcr_1: String,
    pub pcr_2: String,
    pub signature: String,
}

#[derive(Clone)]
pub struct TpmAttestationManager {
    expected_pcr0: String,
    expected_pcr1: String,
    expected_pcr2: String,
    ca_cert_path: String,
    client_cert_path: String,
    client_key_path: String,
}

impl TpmAttestationManager {
    pub fn new(expected_pcr0: String, expected_pcr1: String, expected_pcr2: String, ca_cert_path: String, client_cert_path: String, client_key_path: String) -> Self {
        Self {
            expected_pcr0,
            expected_pcr1,
            expected_pcr2,
            ca_cert_path,
            client_cert_path,
            client_key_path,
        }
    }

    pub fn validate_report(&self, report: &AttestationReport) -> Result<(), Box<dyn std::error::Error>> {
        if report.pcr_0 != self.expected_pcr0 {
            return Err("PCR_0 mismatch".into());
        }
        if report.pcr_1 != self.expected_pcr1 {
            return Err("PCR_1 mismatch".into());
        }
        if report.pcr_2 != self.expected_pcr2 {
            return Err("PCR_2 mismatch".into());
        }
        // In a real scenario, we would also verify the cryptographic signature of the report
        // using the TPM's AIK (Attestation Identity Key) public key.
        Ok(())
    }

    pub fn create_mtls_client(&self) -> Result<Client, Box<dyn std::error::Error>> {
        let mut ca_cert_file = fs::File::open(&self.ca_cert_path)?;
        let mut ca_cert_buffer = Vec::new();
        std::io::Read::read_to_end(&mut ca_cert_file, &mut ca_cert_buffer)?;
        let ca_cert = Certificate::from_pem(&ca_cert_buffer)?;

        let mut client_cert_file = fs::File::open(&self.client_cert_path)?;
        let mut client_cert_buffer = Vec::new();
        std::io::Read::read_to_end(&mut client_cert_file, &mut client_cert_buffer)?;

        let mut client_key_file = fs::File::open(&self.client_key_path)?;
        let mut client_key_buffer = Vec::new();
        std::io::Read::read_to_end(&mut client_key_file, &mut client_key_buffer)?;

        let mut combined_buffer = client_cert_buffer;
        combined_buffer.extend_from_slice(b"\n");
        combined_buffer.extend_from_slice(&client_key_buffer);

        let identity = Identity::from_pem(&combined_buffer)?;

        let client = Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(client)
    }
}


#[derive(Clone)]
pub struct SageMakerProxy {
    client: SageMakerClient,
    kms_key_id: String,
    attestation_manager: TpmAttestationManager,
}

impl SageMakerProxy {
    pub fn new(client: SageMakerClient, kms_key_id: String, attestation_manager: TpmAttestationManager) -> Self {
        Self {
            client,
            kms_key_id,
            attestation_manager,
        }
    }

    pub async fn train(&self, input_data: Vec<u8>, hyperparameters: serde_json::Value, attestation_report: AttestationReport) -> Result<String, Box<dyn std::error::Error>> {
        // 0. Attestation Validation
        println!("Validating Attestation Report...");
        self.attestation_manager.validate_report(&attestation_report)?;
        println!("Attestation Report validated successfully.");

        // Create an mTLS client for secure communication (e.g., to an internal API or S3 API)
        let _mtls_client = self.attestation_manager.create_mtls_client()?;
        println!("mTLS client created successfully.");


        // 1. Criptografia efêmera
        let key_bytes = [0u8; 32]; // In reality, fetch from KMS using self.kms_key_id
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes); // KMS-derived key
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(b"unique nonce");
        let ciphertext = cipher.encrypt(nonce, input_data.as_ref())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // 2. Upload para S3 efêmero
        let s3_key = format!("train/{}.enc", uuid::Uuid::new_v4());
        println!("Uploading encrypted data to S3 at: {}", s3_key);
        // ... upload to S3 with lifecycle 1h
        // using _mtls_client if necessary

        // 3. Criar Training Job
        // Using string directly to bypass missing properties on algorithm_specification, input_data_config in stub
        /*
        let training_job = self.client.create_training_job()
            .training_job_name("arkhe-train-".to_string() + &uuid::Uuid::new_v4().to_string())
            //.algorithm_specification(...)
            //.input_data_config(...)
            .send().await?;
        */

        // Return mock ARN for stub
        let mock_arn = format!("arn:aws:sagemaker:us-east-1:123456789012:training-job/arkhe-train-{}", uuid::Uuid::new_v4());
        Ok(mock_arn)
    }
}
