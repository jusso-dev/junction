//! Central cloud endpoints. Endpoint URLs and token audiences are distinct values.
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MicrosoftCloud {
    Public,
    UsGovernment,
    UsGovernmentDod,
    China,
    Custom,
}
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CloudService {
    Graph,
    Arm,
    DefenderXdr,
    DefenderEndpoint,
    AzureDevops,
    Fabric,
    PowerPlatform,
    PowerBi,
    LogAnalytics,
    Office365Management,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceEndpoint {
    pub endpoint: String,
    /// None means authoritative audience metadata is not yet available.
    pub audience: Option<String>,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudEndpoints {
    pub authority: String,
    pub graph: Option<ServiceEndpoint>,
    pub arm: Option<ServiceEndpoint>,
    pub defender_xdr: Option<ServiceEndpoint>,
    pub defender_endpoint: Option<ServiceEndpoint>,
    #[serde(default)]
    pub azure_devops: Option<ServiceEndpoint>,
    #[serde(default)]
    pub fabric: Option<ServiceEndpoint>,
    #[serde(default)]
    pub power_platform: Option<ServiceEndpoint>,
    #[serde(default)]
    pub power_bi: Option<ServiceEndpoint>,
    #[serde(default)]
    pub log_analytics: Option<ServiceEndpoint>,
    #[serde(default)]
    pub office365_management: Option<ServiceEndpoint>,
    pub storage_suffix: Option<String>,
    pub key_vault_suffix: Option<String>,
}
fn service(endpoint: &str, audience: Option<&str>) -> Option<ServiceEndpoint> {
    Some(ServiceEndpoint {
        endpoint: endpoint.into(),
        audience: audience.map(str::to_owned),
    })
}
impl MicrosoftCloud {
    /// Custom clouds require explicit operator configuration; there is no public fallback.
    pub fn endpoints(self) -> Result<CloudEndpoints> {
        let (authority, graph, arm, arm_audience, storage, vault) = match self {
            Self::Public => (
                "https://login.microsoftonline.com",
                "https://graph.microsoft.com",
                "https://management.azure.com",
                "https://management.core.windows.net/",
                "core.windows.net",
                "vault.azure.net",
            ),
            Self::UsGovernment => (
                "https://login.microsoftonline.us",
                "https://graph.microsoft.us",
                "https://management.usgovcloudapi.net",
                "https://management.core.usgovcloudapi.net/",
                "core.usgovcloudapi.net",
                "vault.usgovcloudapi.net",
            ),
            Self::UsGovernmentDod => (
                "https://login.microsoftonline.us",
                "https://dod-graph.microsoft.us",
                "https://management.usgovcloudapi.net",
                "https://management.core.usgovcloudapi.net/",
                "core.usgovcloudapi.net",
                "vault.usgovcloudapi.net",
            ),
            Self::China => (
                "https://login.chinacloudapi.cn",
                "https://microsoftgraph.chinacloudapi.cn",
                "https://management.chinacloudapi.cn",
                "https://management.core.chinacloudapi.cn/",
                "core.chinacloudapi.cn",
                "vault.azure.cn",
            ),
            Self::Custom => bail!("custom cloud requires endpoint configuration"),
        };
        let (defender_xdr, defender_endpoint) = match self {
            Self::Public => (
                service(
                    "https://api.security.microsoft.com",
                    Some("https://api.security.microsoft.com"),
                ),
                service(
                    "https://api.securitycenter.microsoft.com",
                    Some("https://api.securitycenter.microsoft.com"),
                ),
            ),
            Self::UsGovernment | Self::UsGovernmentDod => (
                service("https://api-gov.security.microsoft.us", None),
                service("https://api-gov.securitycenter.microsoft.us", None),
            ),
            _ => (None, None),
        };
        Ok(CloudEndpoints {
            authority: authority.into(),
            graph: service(graph, Some(graph)),
            arm: service(arm, Some(arm_audience)),
            defender_xdr,
            defender_endpoint,
            azure_devops: if self == Self::Public {
                service(
                    "https://dev.azure.com",
                    Some("499b84ac-1321-427f-aa17-267ca6975798"),
                )
            } else {
                None
            },
            storage_suffix: Some(storage.into()),
            fabric: if self == Self::Public {
                service(
                    "https://api.fabric.microsoft.com",
                    Some("https://api.fabric.microsoft.com"),
                )
            } else {
                None
            },
            key_vault_suffix: Some(vault.into()),
            power_platform: if self == Self::Public {
                service(
                    "https://api.powerplatform.com",
                    Some("https://api.powerplatform.com"),
                )
            } else {
                None
            },
            power_bi: match self {
                Self::Public => service(
                    "https://api.powerbi.com",
                    Some("https://analysis.windows.net/powerbi/api"),
                ),
                Self::UsGovernment => service(
                    "https://api.powerbigov.us",
                    Some("https://analysis.usgovcloudapi.net/powerbi/api"),
                ),
                Self::China => service(
                    "https://api.powerbi.cn",
                    Some("https://analysis.chinacloudapi.cn/powerbi/api"),
                ),
                _ => None,
            },
            log_analytics: match self {
                Self::Public => service(
                    "https://api.loganalytics.io",
                    Some("https://api.loganalytics.io"),
                ),
                Self::UsGovernment | Self::UsGovernmentDod => service(
                    "https://api.loganalytics.us",
                    Some("https://api.loganalytics.us"),
                ),
                Self::China => service(
                    "https://api.loganalytics.azure.cn",
                    Some("https://api.loganalytics.azure.cn"),
                ),
                Self::Custom => None,
            },
            office365_management: match self {
                Self::Public => service(
                    "https://manage.office.com",
                    Some("https://manage.office.com"),
                ),
                Self::UsGovernment => service(
                    "https://manage.office365.us",
                    Some("https://manage.office365.us"),
                ),
                Self::UsGovernmentDod => service(
                    "https://manage.protection.apps.mil",
                    Some("https://manage.protection.apps.mil"),
                ),
                _ => None,
            },
        })
    }
}
impl CloudEndpoints {
    pub fn validate(&self) -> Result<()> {
        validate_endpoint(&self.authority, true)?;
        for target in [
            &self.graph,
            &self.arm,
            &self.defender_xdr,
            &self.defender_endpoint,
            &self.azure_devops,
            &self.fabric,
            &self.power_platform,
            &self.power_bi,
            &self.log_analytics,
            &self.office365_management,
        ]
        .into_iter()
        .flatten()
        {
            validate_endpoint(&target.endpoint, false)?;
            if let Some(audience) = &target.audience {
                let application_id = audience.len() == 36
                    && audience.bytes().enumerate().all(|(index, byte)| {
                        if matches!(index, 8 | 13 | 18 | 23) {
                            byte == b'-'
                        } else {
                            byte.is_ascii_hexdigit()
                        }
                    });
                if !application_id {
                    validate_endpoint(audience, false)?;
                }
            }
        }
        for suffix in [&self.storage_suffix, &self.key_vault_suffix]
            .into_iter()
            .flatten()
        {
            if suffix.is_empty()
                || suffix.split('.').any(|part| {
                    part.is_empty()
                        || part.starts_with('-')
                        || part.ends_with('-')
                        || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
            {
                bail!("invalid cloud suffix");
            }
        }
        Ok(())
    }
    pub fn target(&self, service: CloudService) -> Result<&ServiceEndpoint> {
        self.validate()?;
        match service {
            CloudService::Graph => &self.graph,
            CloudService::Arm => &self.arm,
            CloudService::DefenderXdr => &self.defender_xdr,
            CloudService::DefenderEndpoint => &self.defender_endpoint,
            CloudService::AzureDevops => &self.azure_devops,
            CloudService::Fabric => &self.fabric,
            CloudService::PowerPlatform => &self.power_platform,
            CloudService::PowerBi => &self.power_bi,
            CloudService::LogAnalytics => &self.log_analytics,
            CloudService::Office365Management => &self.office365_management,
        }
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("service unavailable in configured cloud"))
    }
    /// Remap an upstream service origin while retaining its version/base path.
    /// Unrecognized upstream hosts are rejected rather than treated as ARM or Graph.
    pub fn resolve(&self, service: CloudService, upstream: &str) -> Result<ServiceEndpoint> {
        let upstream = validate_endpoint(upstream, false)?;
        let mut recognized = false;
        for cloud in [
            MicrosoftCloud::Public,
            MicrosoftCloud::UsGovernment,
            MicrosoftCloud::UsGovernmentDod,
            MicrosoftCloud::China,
        ] {
            if let Ok(target) = cloud.endpoints()?.target(service) {
                let known = Url::parse(&target.endpoint)?;
                recognized |= known.origin() == upstream.origin();
            }
        }
        let target = self.target(service)?;
        let mut endpoint = Url::parse(&target.endpoint)?;
        recognized |= endpoint.origin() == upstream.origin();
        if !recognized {
            bail!("operation endpoint does not match configured service");
        }
        if target.audience.is_none() {
            bail!("service audience requires explicit configuration");
        }
        endpoint.set_path(&format!(
            "{}{}",
            endpoint.path().trim_end_matches('/'),
            upstream.path()
        ));
        Ok(ServiceEndpoint {
            endpoint: endpoint.to_string(),
            audience: target.audience.clone(),
        })
    }
}
fn validate_endpoint(value: &str, origin_only: bool) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| anyhow::anyhow!("invalid cloud endpoint"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (origin_only && url.path() != "/")
    {
        bail!("invalid cloud endpoint");
    }
    Ok(url)
}
#[cfg(test)]
mod tests {
    #[test]
    fn fabric_has_a_service_audience_without_sovereign_fallback() {
        use super::*;
        let public = MicrosoftCloud::Public.endpoints().unwrap();
        let target = public
            .resolve(CloudService::Fabric, "https://api.fabric.microsoft.com/v1/")
            .unwrap();
        assert_eq!(target.endpoint, "https://api.fabric.microsoft.com/v1/");
        assert_eq!(
            target.audience.as_deref(),
            Some("https://api.fabric.microsoft.com")
        );
        assert!(
            public
                .resolve(CloudService::Fabric, "https://graph.microsoft.com/v1/")
                .is_err()
        );
        for cloud in [
            MicrosoftCloud::UsGovernment,
            MicrosoftCloud::UsGovernmentDod,
            MicrosoftCloud::China,
        ] {
            assert!(
                cloud
                    .endpoints()
                    .unwrap()
                    .resolve(CloudService::Fabric, "https://api.fabric.microsoft.com/v1/")
                    .is_err()
            );
        }
        let mut legacy = serde_json::to_value(public).unwrap();
        legacy.as_object_mut().unwrap().remove("fabric");
        let legacy: CloudEndpoints = serde_json::from_value(legacy).unwrap();
        assert!(legacy.target(CloudService::Fabric).is_err());
    }
    #[test]
    fn devops_public_endpoint_uses_explicit_resource_id() {
        use super::*;
        let endpoints = MicrosoftCloud::Public.endpoints().unwrap();
        let target = endpoints
            .resolve(CloudService::AzureDevops, "https://dev.azure.com/")
            .unwrap();
        assert_eq!(target.endpoint, "https://dev.azure.com/");
        assert_eq!(
            target.audience.as_deref(),
            Some("499b84ac-1321-427f-aa17-267ca6975798")
        );
        for cloud in [
            MicrosoftCloud::UsGovernment,
            MicrosoftCloud::UsGovernmentDod,
            MicrosoftCloud::China,
        ] {
            assert!(
                cloud
                    .endpoints()
                    .unwrap()
                    .target(CloudService::AzureDevops)
                    .is_err()
            );
        }
        assert!(
            endpoints
                .resolve(CloudService::AzureDevops, "https://attacker.example/")
                .is_err()
        );
        let mut invalid = endpoints;
        invalid.azure_devops.as_mut().unwrap().audience =
            Some("499b84ac-1321-427f-aa17-267ca697579Z".into());
        assert!(invalid.validate().is_err());
    }
    use super::*;
    #[test]
    fn data_plane_services_map_endpoints_and_audiences() {
        let public = MicrosoftCloud::Public.endpoints().unwrap();
        for (service, upstream, audience) in [
            (
                CloudService::PowerPlatform,
                "https://api.powerplatform.com/",
                "https://api.powerplatform.com",
            ),
            (
                CloudService::PowerBi,
                "https://api.powerbi.com/",
                "https://analysis.windows.net/powerbi/api",
            ),
            (
                CloudService::LogAnalytics,
                "https://api.loganalytics.io/v1",
                "https://api.loganalytics.io",
            ),
            (
                CloudService::Office365Management,
                "https://manage.office.com/",
                "https://manage.office.com",
            ),
        ] {
            let target = public.resolve(service, upstream).unwrap();
            assert_eq!(target.audience.as_deref(), Some(audience));
            assert!(
                public
                    .resolve(service, "https://graph.microsoft.com/")
                    .is_err()
            );
        }
        let government = MicrosoftCloud::UsGovernment.endpoints().unwrap();
        let target = government
            .resolve(CloudService::LogAnalytics, "https://api.loganalytics.io/v1")
            .unwrap();
        assert_eq!(target.endpoint, "https://api.loganalytics.us/v1");
        assert!(government.target(CloudService::PowerPlatform).is_err());
    }
    #[test]
    fn sovereign_mapping_preserves_version_paths_and_audience_separation() {
        for (cloud, host) in [
            (MicrosoftCloud::UsGovernment, "graph.microsoft.us"),
            (MicrosoftCloud::UsGovernmentDod, "dod-graph.microsoft.us"),
            (MicrosoftCloud::China, "microsoftgraph.chinacloudapi.cn"),
        ] {
            let endpoints = cloud.endpoints().unwrap();
            endpoints.validate().unwrap();
            let graph = endpoints
                .resolve(CloudService::Graph, "https://graph.microsoft.com/v1.0")
                .unwrap();
            assert_eq!(graph.endpoint, format!("https://{host}/v1.0"));
            assert_eq!(
                graph.audience.as_deref(),
                Some(format!("https://{host}").as_str())
            );
            let arm = endpoints
                .resolve(CloudService::Arm, "https://management.azure.com/")
                .unwrap();
            assert_ne!(arm.endpoint, arm.audience.unwrap());
        }
    }
    #[test]
    fn unavailable_custom_and_mismatched_services_fail_closed() {
        assert!(MicrosoftCloud::Custom.endpoints().is_err());
        let china = MicrosoftCloud::China.endpoints().unwrap();
        assert!(china.target(CloudService::DefenderXdr).is_err());
        let gov = MicrosoftCloud::UsGovernment.endpoints().unwrap();
        assert!(
            gov.resolve(
                CloudService::DefenderXdr,
                "https://api.security.microsoft.com"
            )
            .is_err()
        );
        assert!(
            gov.resolve(CloudService::Graph, "https://management.azure.com")
                .is_err()
        );
        assert!(
            gov.resolve(CloudService::Graph, "https://attacker.example")
                .is_err()
        );
        let mut custom = gov;
        custom.authority = "https://login.example.com".into();
        custom.graph = service(
            "https://graph.example.com",
            Some("https://graph-audience.example.com"),
        );
        let resolved = custom
            .resolve(CloudService::Graph, "https://graph.microsoft.com/v1.0")
            .unwrap();
        assert_eq!(resolved.endpoint, "https://graph.example.com/v1.0");
        assert_eq!(
            resolved.audience.as_deref(),
            Some("https://graph-audience.example.com")
        );
        custom.authority = "https://login.example.com?secret=x".into();
        assert!(custom.validate().is_err());
    }
}
