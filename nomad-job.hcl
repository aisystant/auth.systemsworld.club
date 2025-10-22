job "auth-gateway" {
  datacenters = ["dc1"]
  type = "service"

  group "web" {
    task "app" {
      driver = "docker"
      
      config {
        image = "ghcr.io/aisystant/auth.systemsworld.club:latest"
        ports = ["http"]
      }
      
      template {
        data = <<EOH
DISCOURSE_CONNECT_SECRET={{ with nomadVar "nomad/jobs/auth-gateway/web/app" }}{{ .DISCOURSE_CONNECT_SECRET | toJSON }}{{ end }}
OIDC_CLIENT_ID={{ with nomadVar "nomad/jobs/auth-gateway/web/app" }}{{ .OIDC_CLIENT_ID | toJSON }}{{ end }}
OIDC_CLIENT_SECRET={{ with nomadVar "nomad/jobs/auth-gateway/web/app" }}{{ .OIDC_CLIENT_SECRET | toJSON }}{{ end }}
OIDC_ISSUER={{ with nomadVar "nomad/jobs/auth-gateway/web/app" }}{{ .OIDC_ISSUER | toJSON }}{{ end }}
EOH
        destination = "${NOMAD_SECRETS_DIR}/app.env"
        env         = true
        change_mode = "restart"
        error_on_missing_key = true
      }

      resources {
        cpu    = 100
        memory = 256
      }
      
      service {
        name = "auth-gateway"
        port = "http"
        
        tags = [
          "traefik.enable=true",
          "traefik.http.routers.auth-gateway.rule=Host(`auth.systemsworld.club`)",
          "traefik.http.routers.auth-gateway.entrypoints=websecure",
          "traefik.http.routers.auth-gateway.tls.certresolver=letsencrypt",
        ]
        
        check {
          type     = "tcp"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
    
    network {
      port "http" {
        static = 8020
        to = 8020
      }
    }
  }
}
