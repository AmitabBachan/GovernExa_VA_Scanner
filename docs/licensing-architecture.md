# Licensing Architecture: GovernExa

This document outlines the software licensing architecture for the GovernExa Vulnerability Scanner platform. The architecture ensures secure distribution, activation, and validation of software licenses using asymmetric cryptography and machine-bound constraints.

## 1. Cryptographic Design (RSA Public/Private Keys)

The licensing system relies on RSA asymmetric cryptography to prevent forgery and unauthorized modifications of license data.

*   **Private Key (Vendor Locally):** The Vendor holds the RSA Private Key in an isolated, secure environment (never distributed with the application). This key is used exclusively to generate and sign the digital licenses.
*   **Public Key (GovernExa Application):** The GovernExa application distribution includes the corresponding RSA Public Key. The application uses this key to independently verify the digital signature of the license payloads. If the signature is invalid, the license is rejected as tampered or forged.

## 2. Activation Flow

License activation links a purchased license to a specific installation. Activation is strictly bound to two hardware/software identifiers to prevent abuse:
*   `installation_id`: A unique identifier generated upon application installation.
*   `machine_fingerprint`: A robust hash of the host machine's hardware identifiers (e.g., CPU ID, Motherboard Serial, MAC Address).

### 2.1 Online Activation
1.  **Input:** The user enters their License Key (or uploads a base license file) into the GovernExa UI.
2.  **Request:** GovernExa gathers the `installation_id` and `machine_fingerprint` and sends them along with the License Key over HTTPS to the Vendor's licensing server.
3.  **Validation & Signing:** The Vendor server verifies the License Key, checks activation limits, and generates an *Activation Payload*. This payload includes the machine identifiers and is signed with the Vendor's **Private Key**.
4.  **Response:** The server returns the signed Activation Payload to the GovernExa application.
5.  **Local Verification:** GovernExa uses the **Public Key** to verify the signature. Once verified, it stores the active license locally.

### 2.2 Offline Activation
For air-gapped or restricted environments, an offline exchange mechanism is provided.
1.  **Export:** The user clicks "Generate Offline Request" in the GovernExa UI. The application generates a JSON file containing the `installation_id`, `machine_fingerprint`, and the base License Key.
2.  **Transfer:** The user physically transfers this JSON request file to an internet-connected machine.
3.  **Vendor Portal:** The user uploads the JSON request file to the Vendor's web portal.
4.  **Signing:** The Vendor portal validates the request and generates a signed *Activation JSON Payload* (signed using the **Private Key**).
5.  **Import:** The user transfers the Activation JSON file back to the air-gapped GovernExa instance and imports it via the UI.
6.  **Local Verification:** GovernExa validates the imported JSON signature using its **Public Key** and completes activation.

## 3. Backend Integration Points

The application backend (FastAPI) handles the enforcement and tracking of license states.

### 3.1 FastAPI Dependencies
To enforce licensing constraints across API routes, specific FastAPI dependencies are implemented:
*   `verify_active_license`: A dependency injected into protected routes that checks if a valid, signed, and machine-verified license exists in the system.
*   `check_feature_entitlement(feature_name)`: A parameterized dependency to check if the current valid license includes rights to specific modules (e.g., advanced reporting, compliance scanning).
*   `validate_machine_fingerprint`: A utility dependency called during license verification to ensure the current host matches the activated `machine_fingerprint`.

### 3.2 Database Tables
The following tables are required to manage licenses locally within the GovernExa database:

*   **`licenses`**: Stores the core license details.
    *   `id` (PK)
    *   `license_key` (String, Unique)
    *   `tier` (String - e.g., Basic, Pro, Enterprise)
    *   `issued_at` (Timestamp)
    *   `expires_at` (Timestamp)
    *   `features` (JSONB - list of entitled features)
    *   `signature` (Text)

*   **`license_activations`**: Tracks active deployments tied to a license.
    *   `id` (PK)
    *   `license_id` (FK to `licenses`)
    *   `installation_id` (String)
    *   `machine_fingerprint` (String)
    *   `activated_at` (Timestamp)
    *   `last_verified_at` (Timestamp)
    *   `status` (Enum: Active, Suspended)

*   **`revoked_licenses`**: Local Certificate Revocation List (CRL) for compromised or refunded licenses.
    *   `id` (PK)
    *   `license_key` (String)
    *   `revoked_at` (Timestamp)
    *   `reason` (String)

*   **`audit_logs`**: Immutable log of licensing events for security and compliance.
    *   `id` (PK)
    *   `event_type` (Enum: Activation_Attempt, Activation_Success, Activation_Failed, License_Expired, Offline_Import)
    *   `description` (Text)
    *   `created_at` (Timestamp)
    *   `ip_address` (String)
    *   `user_id` (FK to Users, Nullable)
