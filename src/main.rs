use actix_web::{web, App, HttpResponse, HttpServer};
use serde::{Serialize};

// Response structures
#[derive(Serialize)]
struct InventoryResponse {
    tower_accounts: i32,
    accounts: i32,
    tenants: i32,
    protectors: i32,
}

#[derive(Serialize)]
struct ThreatResponse {
    severity: String,
    count: i32,
    status: String,
}

#[derive(Serialize)]
struct VulnerabilityResponse {
    cve_id: String,
    severity: String,
    description: String,
    affected_hosts: i32,
}

#[derive(Serialize)]
struct HostResponse {
    hostname: String,
    ip_address: String,
    status: String,
    os: String,
}

#[derive(Serialize)]
struct RiskAssessmentResponse {
    total_score: i32,
    high_risks: i32,
    medium_risks: i32,
    low_risks: i32,
}

// API Handlers
async fn get_inventory() -> HttpResponse {
    let response = InventoryResponse {
        tower_accounts: 5,
        accounts: 25,
        tenants: 100,
        protectors: 500,
    };
    HttpResponse::Ok().json(response)
}

async fn get_threats() -> HttpResponse {
    let threats = vec![
        ThreatResponse {
            severity: "Critical".to_string(),
            count: 3,
            status: "Active".to_string(),
        },
        ThreatResponse {
            severity: "High".to_string(),
            count: 7,
            status: "Active".to_string(),
        },
        ThreatResponse {
            severity: "Medium".to_string(),
            count: 15,
            status: "Active".to_string(),
        },
    ];
    HttpResponse::Ok().json(threats)
}

async fn get_vulnerabilities() -> HttpResponse {
    let vulns = vec![
        VulnerabilityResponse {
            cve_id: "CVE-2024-0001".to_string(),
            severity: "High".to_string(),
            description: "Remote Code Execution Vulnerability".to_string(),
            affected_hosts: 12,
        },
        VulnerabilityResponse {
            cve_id: "CVE-2024-0002".to_string(),
            severity: "Critical".to_string(),
            description: "Buffer Overflow Vulnerability".to_string(),
            affected_hosts: 5,
        },
    ];
    HttpResponse::Ok().json(vulns)
}

async fn get_hosts() -> HttpResponse {
    let hosts = vec![
        HostResponse {
            hostname: "SERVER-001".to_string(),
            ip_address: "192.168.1.100".to_string(),
            status: "Protected".to_string(),
            os: "Windows Server 2019".to_string(),
        },
        HostResponse {
            hostname: "SERVER-002".to_string(),
            ip_address: "192.168.1.101".to_string(),
            status: "Protected".to_string(),
            os: "Ubuntu 20.04".to_string(),
        },
    ];
    HttpResponse::Ok().json(hosts)
}

async fn get_risk_assessment() -> HttpResponse {
    let assessment = RiskAssessmentResponse {
        total_score: 85,
        high_risks: 3,
        medium_risks: 7,
        low_risks: 12,
    };
    HttpResponse::Ok().json(assessment)
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({ "status": "healthy" }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting mock server at http://127.0.0.1:8080");
    
    HttpServer::new(|| {
        App::new()
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