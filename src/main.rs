use actix_cors::Cors;
use actix_web::{http::header, middleware, web, App, HttpResponse, HttpServer};
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

// Response Structures
#[derive(Serialize)]
struct InventoryResponse {
    tower_accounts: i32,
    accounts: i32,
    tenants: i32,
    protectors: i32,
    active_endpoints: i32,
    managed_devices: i32,
    security_policies: i32,
    security_groups: i32,
}

#[derive(Serialize)]
struct ThreatResponse {
    severity: String,
    count: i32,
    status: String,
    threat_type: String,
    detection_source: String,
    first_seen: u64,
    last_seen: u64,
    mitre_tactics: Vec<String>,
    affected_assets: Vec<String>,
}

#[derive(Serialize)]
struct VulnerabilityResponse {
    cve_id: String,
    severity: String,
    description: String,
    affected_hosts: i32,
    cvss_score: f32,
    exploit_available: bool,
    patch_available: bool,
    remediation_steps: String,
    detection_date: u64,
    asset_types: Vec<String>,
}

#[derive(Serialize)]
struct HostResponse {
    hostname: String,
    ip_address: String,
    status: String,
    os: String,
    last_seen: u64,
    security_agent_version: String,
    compliance_status: bool,
    security_incidents: i32,
    open_vulnerabilities: i32,
    risk_score: i32,
    tags: Vec<String>,
}

#[derive(Serialize)]
struct RiskAssessmentResponse {
    total_score: i32,
    high_risks: i32,
    medium_risks: i32,
    low_risks: i32,
    risk_factors: Vec<RiskFactor>,
    trend: String,
    last_assessment: u64,
    compliance_status: ComplianceStatus,
}

#[derive(Serialize)]
struct RiskFactor {
    category: String,
    score: i32,
    severity: String,
    recommendations: Vec<String>,
}

#[derive(Serialize)]
struct ComplianceStatus {
    frameworks: Vec<String>,
    compliant_controls: i32,
    non_compliant_controls: i32,
    pending_reviews: i32,
}

// API Handlers
async fn health() -> HttpResponse {
    let health_data = serde_json::json!({
        "status": "healthy",
        "timestamp": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        "version": env!("CARGO_PKG_VERSION"),
        "services": {
            "database": "connected",
            "cache": "operational",
            "security_engine": "running"
        }
    });
    HttpResponse::Ok().json(health_data)
}

async fn get_inventory() -> HttpResponse {
    let response = InventoryResponse {
        tower_accounts: 5,
        accounts: 25,
        tenants: 100,
        protectors: 500,
        active_endpoints: 1500,
        managed_devices: 2000,
        security_policies: 50,
        security_groups: 30,
    };
    HttpResponse::Ok().json(response)
}

async fn get_threats() -> HttpResponse {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let threats = vec![
        ThreatResponse {
            severity: "Critical".to_string(),
            count: 3,
            status: "Active".to_string(),
            threat_type: "Ransomware".to_string(),
            detection_source: "EDR".to_string(),
            first_seen: current_time - 3600,
            last_seen: current_time,
            mitre_tactics: vec!["Initial Access".to_string(), "Execution".to_string()],
            affected_assets: vec!["SERVER-001".to_string(), "WORKSTATION-042".to_string()],
        },
        ThreatResponse {
            severity: "High".to_string(),
            count: 7,
            status: "Active".to_string(),
            threat_type: "Data Exfiltration".to_string(),
            detection_source: "NDR".to_string(),
            first_seen: current_time - 7200,
            last_seen: current_time - 1800,
            mitre_tactics: vec!["Exfiltration".to_string(), "Command and Control".to_string()],
            affected_assets: vec!["SERVER-003".to_string()],
        },
    ];
    HttpResponse::Ok().json(threats)
}

async fn get_vulnerabilities() -> HttpResponse {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let vulns = vec![
        VulnerabilityResponse {
            cve_id: "CVE-2024-0001".to_string(),
            severity: "High".to_string(),
            description: "Remote Code Execution Vulnerability".to_string(),
            affected_hosts: 12,
            cvss_score: 8.9,
            exploit_available: true,
            patch_available: true,
            remediation_steps: "Apply security patch KB123456".to_string(),
            detection_date: current_time - 86400,
            asset_types: vec!["Windows Server".to_string(), "Web Server".to_string()],
        },
        VulnerabilityResponse {
            cve_id: "CVE-2024-0002".to_string(),
            severity: "Critical".to_string(),
            description: "Buffer Overflow Vulnerability".to_string(),
            affected_hosts: 5,
            cvss_score: 9.8,
            exploit_available: true,
            patch_available: false,
            remediation_steps: "Implement memory protection controls".to_string(),
            detection_date: current_time - 43200,
            asset_types: vec!["Linux Server".to_string(), "Application Server".to_string()],
        },
    ];
    HttpResponse::Ok().json(vulns)
}

async fn get_hosts() -> HttpResponse {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let hosts = vec![
        HostResponse {
            hostname: "SERVER-001".to_string(),
            ip_address: "192.168.1.100".to_string(),
            status: "Protected".to_string(),
            os: "Windows Server 2019".to_string(),
            last_seen: current_time - 300,
            security_agent_version: "3.5.1".to_string(),
            compliance_status: true,
            security_incidents: 2,
            open_vulnerabilities: 5,
            risk_score: 75,
            tags: vec!["production".to_string(), "critical-asset".to_string()],
        },
        HostResponse {
            hostname: "SERVER-002".to_string(),
            ip_address: "192.168.1.101".to_string(),
            status: "Protected".to_string(),
            os: "Ubuntu 20.04".to_string(),
            last_seen: current_time - 180,
            security_agent_version: "3.5.1".to_string(),
            compliance_status: true,
            security_incidents: 0,
            open_vulnerabilities: 2,
            risk_score: 45,
            tags: vec!["staging".to_string(), "web-server".to_string()],
        },
    ];
    HttpResponse::Ok().json(hosts)
}

async fn get_risk_assessment() -> HttpResponse {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let assessment = RiskAssessmentResponse {
        total_score: 85,
        high_risks: 3,
        medium_risks: 7,
        low_risks: 12,
        risk_factors: vec![
            RiskFactor {
                category: "Endpoint Security".to_string(),
                score: 75,
                severity: "High".to_string(),
                recommendations: vec![
                    "Update EDR agents on 15 endpoints".to_string(),
                    "Enable memory protection on critical servers".to_string(),
                ],
            },
            RiskFactor {
                category: "Network Security".to_string(),
                score: 82,
                severity: "Medium".to_string(),
                recommendations: vec![
                    "Review firewall rules".to_string(),
                    "Implement network segmentation".to_string(),
                ],
            },
        ],
        trend: "Improving".to_string(),
        last_assessment: current_time - 3600,
        compliance_status: ComplianceStatus {
            frameworks: vec!["ISO 27001".to_string(), "NIST CSF".to_string()],
            compliant_controls: 85,
            non_compliant_controls: 12,
            pending_reviews: 8,
        },
    };
    HttpResponse::Ok().json(assessment)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting secure API server at http://127.0.0.1:8080");

    HttpServer::new(|| {
        // Configure CORS
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET"])
            .allowed_headers(vec![header::AUTHORIZATION, header::ACCEPT])
            .allowed_header(header::CONTENT_TYPE)
            .max_age(3600);

        App::new()
            .wrap(cors)
            .wrap(middleware::Logger::default())
            // Security headers middleware
            .wrap(middleware::DefaultHeaders::new()
                .add((header::X_XSS_PROTECTION, "1; mode=block"))
                .add((header::X_FRAME_OPTIONS, "DENY"))
                .add((header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
                .add((header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains"))
                .add(("Permissions-Policy", "geolocation=(), microphone=()"))
                .add(("Content-Security-Policy", "default-src 'self'")))
            .route("/health", web::get().to(health))
            .service(
                web::scope("/api/v1")
                    .route("/dashboard/accounts/inventory", web::get().to(get_inventory))
                    .route("/dashboard/countThreatsBySeverity", web::get().to(get_threats))
                    .route("/vulnerabilities/inventory", web::get().to(get_vulnerabilities))
                    .route("/hosts/inventory/list", web::get().to(get_hosts))
                    .route("/risk-dashboard/vulnerability-assessment", web::get().to(get_risk_assessment))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}