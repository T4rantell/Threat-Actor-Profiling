# Threat-Actor-Profiling

# Threat Actor Profiling - APT Research

Comprehensive threat intelligence profiles of Advanced Persistent Threat (APT) groups based on publicly available OSINT sources.

## Overview

This repository contains detailed analysis and profiling of state-sponsored threat actors, focusing on their tactics, techniques, procedures (TTPs), malware families, and historical campaigns. Each profile is compiled from official government advisories, cybersecurity vendor reports, and public research.

## Current Profiles

- **APT28 (Fancy Bear)** - Russian GRU-affiliated threat actor
  - In-depth analysis of the "Nearest Neighbor Campaign"
  - Focus on espionage operations targeting government and critical infrastructure
  
- **APT29 (Cozy Bear)** - Russian SVR-affiliated threat actor
  - Detailed examination of the SolarWinds "StellarParticle" supply chain attack
  - Analysis of sophisticated intelligence collection operations

## Profile Structure

Each threat actor profile includes:

- **Metadata**: TLP classification, confidence level, attribution
- **Threat Actor Overview**: Origins, motivations, capabilities
- **Historical Campaigns**: Timeline of significant operations with detailed analysis
- **TTPs**: MITRE ATT&CK framework mapping
- **Malware Arsenal**: Technical analysis of tools and implants
- **Detection & Mitigation**: Defensive recommendations and indicators
- **YARA Rules**: Detection signatures for malware families
- **References**: Comprehensive source documentation

## Use Cases

- **Security Research**: Understanding adversary behavior and capabilities
- **Threat Intelligence**: Building institutional knowledge on APT groups
- **Defensive Planning**: Informing security architecture and detection strategies
- **Education**: Learning real-world cyber espionage techniques and attribution methods
- **Incident Response**: Comparing TTPs during investigations

## Methodology

All profiles are compiled exclusively from:
- Official government advisories (CISA, NSA, FBI, NCSC)
- Cybersecurity vendor threat reports (FireEye, CrowdStrike, Microsoft, etc.)
- Public vulnerability databases (CVE, MITRE ATT&CK)
- Academic research and journalistic investigations
- Court documents and indictments

## Disclaimer

**Important**: These profiles are compiled from publicly available open-source intelligence (OSINT) for educational and research purposes only.

- Information is based on publicly disclosed sources and vendor reports
- Attribution is based on consensus from multiple authoritative sources
- TTPs and IoCs should be validated before operational use
- This material is for defensive cybersecurity purposes
- Not affiliated with any government or intelligence agency

## Contributing

Contributions are welcome for:
- Additional APT group profiles
- Updates to existing profiles based on new public disclosures
- Corrections or clarifications with proper sourcing
- Additional YARA rules and detection logic

Please ensure all contributions:
- Use only publicly available sources
- Include proper citations and references
- Follow the established profile structure
- Maintain objectivity and factual accuracy

## Future Additions

Planned profiles include:
- APT34 (OilRig)
- APT37 (Reaper)
- APT38 (Lazarus Group - Financial)
- APT41 (Double Dragon)
- And more...

## References & Resources

- [MITRE ATT&CK Groups](https://attack.mitre.org/groups/)
- [CISA Threat Actor Advisories](https://www.cisa.gov/topics/cyber-threats-and-advisories)
- [FireEye Threat Research](https://www.mandiant.com/resources/blog)
- [CrowdStrike Adversary Intelligence](https://www.crowdstrike.com/adversaries/)

## License

This project is released under MIT License - see [LICENSE](LICENSE) for details.

The content is compiled from publicly available sources. All original research and vendor reports remain property of their respective owners.

---

**Compiled for educational and defensive cybersecurity purposes**

*Last updated: December 2025*
```
