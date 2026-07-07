"""
core/nigerian_brands.py - Official Nigerian Domains & Brand Registry
Author: Joshua Akadri

This module contains verified official domains for major Nigerian institutions
to enable fast official vs impersonation detection.
"""

from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class NigerianBrand:
    """Represents a legitimate Nigerian brand with its official domain(s)."""
    name: str
    category: str
    official_domains: List[str]
    official_domains_set: Set[str] = field(default_factory=set)
    common_typos: List[str] = field(default_factory=list)
    description: str = ""

    def __post_init__(self):
        self.official_domains_set = set(d.lower() for d in self.official_domains)

    def is_official(self, domain: str) -> bool:
        return domain.lower() in self.official_domains_set

    def is_lookalike(self, domain: str) -> bool:
        """Check if domain looks like a typosquat of this brand."""
        domain_l = domain.lower()
        brand_name_l = self.name.lower().replace(" ", "")
        return any(t in domain_l for t in self.common_typos) or (
            brand_name_l in domain_l and domain_l not in self.official_domains_set
        )


# ── NIGERIAN BANKS ──────────────────────────────────────────────────────────

BANKS: List[NigerianBrand] = [
    NigerianBrand(
        name="Access Bank",
        category="bank",
        official_domains=["accessbankplc.com", "mybank.accessbankplc.com", "accessmore.com"],
        common_typos=["accesssbank", "acccessbank", "acessbank", "access-bank-ng"],
        description="Access Bank Plc - Tier 1 Nigerian bank",
    ),
    NigerianBrand(
        name="GTBank / Guaranty Trust",
        category="bank",
        official_domains=["gtbank.com", "guarantytrustbank.com", "ibank.gtbank.com"],
        common_typos=["gtbankng", "g-tbank", "gtb4nk", "gtbhank"],
        description="Guaranty Trust Bank Plc",
    ),
    NigerianBrand(
        name="First Bank of Nigeria",
        category="bank",
        official_domains=["firstbanknigeria.com", "ibank.firstbanknigeria.com"],
        common_typos=["firstbanknig", "1stbanknigeria", "firstbanknlgeria"],
        description="First Bank of Nigeria Limited",
    ),
    NigerianBrand(
        name="Zenith Bank",
        category="bank",
        official_domains=["zenithbank.com", "ibank.zenithbank.com"],
        common_typos=["zenithb4nk", "zennithbank", "zenithbankng"],
        description="Zenith Bank Plc",
    ),
    NigerianBrand(
        name="UBA - United Bank for Africa",
        category="bank",
        official_domains=["ubagroup.com", "ubanigeria.com"],
        common_typos=["u-b-a", "ubang", "uba-nigeria"],
        description="United Bank for Africa Plc",
    ),
    NigerianBrand(
        name="Ecobank Nigeria",
        category="bank",
        official_domains=["ecobank.com", "ecobanknigeria.com"],
        common_typos=["eco-bank", "ecobaank", "ekobank"],
        description="Ecobank Nigeria",
    ),
    NigerianBrand(
        name="FCMB",
        category="bank",
        official_domains=["fcmb.com", "ibank.fcmb.com"],
        common_typos=["fcmbnigeria", "f-cmb", "fcmbb"],
        description="First City Monument Bank",
    ),
    NigerianBrand(
        name="Fidelity Bank",
        category="bank",
        official_domains=["fidelitybank.ng"],
        common_typos=["fidelity-bank", "fidelitybankng", "fidelityb4nk"],
        description="Fidelity Bank Plc",
    ),
    NigerianBrand(
        name="Stanbic IBTC",
        category="bank",
        official_domains=["stanbicibtc.com", "stanbicibtcbank.com"],
        common_typos=["stanbic-ibtc", "stanbicibtcng"],
        description="Stanbic IBTC Holdings",
    ),
    NigerianBrand(
        name="Sterling Bank",
        category="bank",
        official_domains=["sterlingbank.com"],
        common_typos=["sterl1ngbank", "sterlingbankng"],
        description="Sterling Bank Plc",
    ),
    NigerianBrand(
        name="Union Bank",
        category="bank",
        official_domains=["unionbankng.com"],
        common_typos=["union-bank-ng", "unionbanknig"],
        description="Union Bank of Nigeria Plc",
    ),
    NigerianBrand(
        name="Wema Bank",
        category="bank",
        official_domains=["wemabank.com", "alat.ng"],
        common_typos=["wema-bank", "alat-ng"],
        description="Wema Bank Plc (also operates ALAT digital bank)",
    ),
    NigerianBrand(
        name="Heritage Bank",
        category="bank",
        official_domains=["hbng.com"],
        common_typos=["heritagebank", "heritage-bank-ng"],
        description="Heritage Bank Limited",
    ),
    NigerianBrand(
        name="Polaris Bank",
        category="bank",
        official_domains=["polarisbanklimited.com"],
        common_typos=["polaris-bank", "polariisbankng"],
        description="Polaris Bank Limited",
    ),
    NigerianBrand(
        name="Unity Bank",
        category="bank",
        official_domains=["unitybankng.com"],
        common_typos=["unity-bank-ng", "unitybanknig"],
        description="Unity Bank Plc",
    ),
    NigerianBrand(
        name="Keystone Bank",
        category="bank",
        official_domains=["keystonebankng.com"],
        common_typos=["keystone-bank", "keystonebankng"],
        description="Keystone Bank Limited",
    ),
    NigerianBrand(
        name="Providus Bank",
        category="bank",
        official_domains=["providusbank.com"],
        common_typos=["providus-bank", "provldusbank"],
        description="Providus Bank Limited",
    ),
]

# ── FINTECHS ─────────────────────────────────────────────────────────────────

FINTECHS: List[NigerianBrand] = [
    NigerianBrand(
        name="Opay",
        category="fintech",
        official_domains=["opayweb.com", "opay.ng"],
        common_typos=["o-pay", "op4y", "opayng", "opayy"],
        description="OPay Digital Services (Opera)",
    ),
    NigerianBrand(
        name="Kuda Bank",
        category="fintech",
        official_domains=["kuda.com"],
        common_typos=["kudabank", "k-uda", "kud4"],
        description="Kuda MFB - The bank of the free",
    ),
    NigerianBrand(
        name="PalmPay",
        category="fintech",
        official_domains=["palmpay.com"],
        common_typos=["palm-pay", "palmp4y", "palmpaynig"],
        description="PalmPay Limited",
    ),
    NigerianBrand(
        name="Moniepoint",
        category="fintech",
        official_domains=["moniepoint.com", "teamapt.com"],
        common_typos=["monie-point", "monlepoint", "moniepo1nt"],
        description="Moniepoint MFB (TeamApt)",
    ),
    NigerianBrand(
        name="Carbon (Paylater)",
        category="fintech",
        official_domains=["getcarbon.co", "paylater.ng"],
        common_typos=["get-carbon", "carbonnig"],
        description="Carbon (formerly Paylater) - Digital lending",
    ),
    NigerianBrand(
        name="Flutterwave",
        category="fintech",
        official_domains=["flutterwave.com"],
        common_typos=["flutter-wave", "flutterwaveng"],
        description="Flutterwave - Payment technology company",
    ),
    NigerianBrand(
        name="Paystack",
        category="fintech",
        official_domains=["paystack.com"],
        common_typos=["pay-stack", "paystackng"],
        description="Paystack (Stripe subsidiary)",
    ),
    NigerianBrand(
        name="Cowrywise",
        category="fintech",
        official_domains=["cowrywise.com"],
        common_typos=["cowry-wise", "cowrywiseng"],
        description="Cowrywise - Savings & investment platform",
    ),
    NigerianBrand(
        name="Piggyvest",
        category="fintech",
        official_domains=["piggyvest.com"],
        common_typos=["piggy-vest", "piggyvest.ng", "p1ggyvest"],
        description="PiggyVest (formerly Piggybank.ng)",
    ),
    NigerianBrand(
        name="Chipper Cash",
        category="fintech",
        official_domains=["chippercash.com"],
        common_typos=["chipper-cash", "chippercashng"],
        description="Chipper Cash - Pan-African P2P transfers",
    ),
    NigerianBrand(
        name="VFD MFB",
        category="fintech",
        official_domains=["vbank.ng"],
        common_typos=["vfd-bank", "v-bank-ng"],
        description="V bank by VFD Microfinance Bank",
    ),
]

# ── GOVERNMENT AGENCIES ──────────────────────────────────────────────────────

GOVERNMENT: List[NigerianBrand] = [
    NigerianBrand(
        name="Central Bank of Nigeria (CBN)",
        category="government",
        official_domains=["cbn.gov.ng"],
        common_typos=["cbn-ng", "centralbankng", "cbn.gov"],
        description="Apex bank of Nigeria",
    ),
    NigerianBrand(
        name="FIRS - Federal Inland Revenue Service",
        category="government",
        official_domains=["firs.gov.ng"],
        common_typos=["firs-ng", "firsnigeria"],
        description="Nigeria's federal tax authority",
    ),
    NigerianBrand(
        name="EFCC - Economic and Financial Crimes Commission",
        category="government",
        official_domains=["efcc.gov.ng"],
        common_typos=["efcc-ng", "efccnigeria"],
        description="Nigeria's financial crimes watchdog",
    ),
    NigerianBrand(
        name="NIMC - National Identity Management Commission",
        category="government",
        official_domains=["nimc.gov.ng", "ninsregister.ng"],
        common_typos=["nimc-ng", "nimcnigeria"],
        description="National Identity Management Commission",
    ),
    NigerianBrand(
        name="NIN Portal",
        category="government",
        official_domains=["enrollment.nimc.gov.ng", "selfservice.nimc.gov.ng"],
        common_typos=["nin-portal", "ninregistration"],
        description="Official NIN enrollment portal",
    ),
    NigerianBrand(
        name="Nigeria Immigration Service",
        category="government",
        official_domains=["immigration.gov.ng"],
        common_typos=["nigeria-immigration", "immigrationnig"],
        description="Nigeria Immigration Service",
    ),
    NigerianBrand(
        name="Nigeria Police Force",
        category="government",
        official_domains=["npf.gov.ng"],
        common_typos=["nigeria-police", "nigeriapolice"],
        description="Nigeria Police Force",
    ),
    NigerianBrand(
        name="FRSC - Federal Road Safety Corps",
        category="government",
        official_domains=["frsc.gov.ng"],
        common_typos=["frscnig", "road-safety-ng"],
        description="Federal Road Safety Corps Nigeria",
    ),
    NigerianBrand(
        name="CAC - Corporate Affairs Commission",
        category="government",
        official_domains=["cac.gov.ng"],
        common_typos=["cac-ng", "cacnigeria"],
        description="Corporate Affairs Commission Nigeria",
    ),
    NigerianBrand(
        name="JAMB - Joint Admissions & Matriculation Board",
        category="government",
        official_domains=["jamb.gov.ng"],
        common_typos=["jamb-ng", "jambnigeria", "jambportal"],
        description="JAMB - Nigeria university admissions board",
    ),
    NigerianBrand(
        name="WAEC Nigeria",
        category="government",
        official_domains=["waecnigeria.org"],
        common_typos=["waec-ng", "waecnigeria.com"],
        description="West African Examinations Council",
    ),
    NigerianBrand(
        name="NECO",
        category="government",
        official_domains=["neco.gov.ng"],
        common_typos=["neconig", "neco-ng"],
        description="National Examinations Council Nigeria",
    ),
    NigerianBrand(
        name="DPR / NUPRC",
        category="government",
        official_domains=["nuprc.gov.ng", "dpr.gov.ng"],
        common_typos=["dprnigeria", "nuprcng"],
        description="Nigerian Upstream Petroleum Regulatory Commission",
    ),
]

# ── TELECOMS ─────────────────────────────────────────────────────────────────

TELECOMS: List[NigerianBrand] = [
    NigerianBrand(
        name="MTN Nigeria",
        category="telecom",
        official_domains=["mtn.com.ng", "mtnonline.com"],
        common_typos=["mtn-ng", "mtnnigerla", "m-t-n"],
        description="MTN Nigeria Communications Plc",
    ),
    NigerianBrand(
        name="Airtel Nigeria",
        category="telecom",
        official_domains=["airtel.com.ng"],
        common_typos=["airtel-ng", "airtelnigerla"],
        description="Airtel Networks Limited",
    ),
    NigerianBrand(
        name="Glo Mobile",
        category="telecom",
        official_domains=["gloworld.com"],
        common_typos=["glo-ng", "glomobile"],
        description="Globacom Nigeria",
    ),
    NigerianBrand(
        name="9mobile",
        category="telecom",
        official_domains=["9mobile.com.ng"],
        common_typos=["nine-mobile", "9mobileng"],
        description="9mobile (formerly Etisalat Nigeria)",
    ),
]

# ── E-COMMERCE & LOGISTICS ───────────────────────────────────────────────────

ECOMMERCE: List[NigerianBrand] = [
    NigerianBrand(
        name="Jumia Nigeria",
        category="ecommerce",
        official_domains=["jumia.com.ng"],
        common_typos=["jumiia", "jumia-ng", "juumia"],
        description="Jumia Nigeria - E-commerce marketplace",
    ),
    NigerianBrand(
        name="Konga",
        category="ecommerce",
        official_domains=["konga.com"],
        common_typos=["kongaonline", "k-onga"],
        description="Konga Online Shopping Limited",
    ),
    NigerianBrand(
        name="DHL Nigeria",
        category="logistics",
        official_domains=["dhl.com"],
        common_typos=["dhl-ng", "dhlnigeria"],
        description="DHL Express Nigeria",
    ),
    NigerianBrand(
        name="GIG Logistics",
        category="logistics",
        official_domains=["giglogistics.com"],
        common_typos=["gig-logistics", "giglogistic"],
        description="GIG Logistics Nigeria",
    ),
]

# ── BETTING PLATFORMS ────────────────────────────────────────────────────────

BETTING: List[NigerianBrand] = [
    NigerianBrand(
        name="Bet9ja",
        category="betting",
        official_domains=["bet9ja.com", "web.bet9ja.com"],
        common_typos=["bet9ja-ng", "bet9|a", "bet-9ja"],
        description="KC Gaming Networks (Bet9ja)",
    ),
    NigerianBrand(
        name="SportyBet",
        category="betting",
        official_domains=["sportybet.com"],
        common_typos=["sporty-bet", "sportybetng"],
        description="SportyBet Nigeria",
    ),
    NigerianBrand(
        name="1xBet Nigeria",
        category="betting",
        official_domains=["1xbet.com"],
        common_typos=["1xbet-ng", "1x-bet"],
        description="1xBet Nigeria",
    ),
    NigerianBrand(
        name="NairaBet",
        category="betting",
        official_domains=["naira.bet", "nairabet.com"],
        common_typos=["naira-bet", "nairabetng"],
        description="NairaBet",
    ),
    NigerianBrand(
        name="BetKing",
        category="betting",
        official_domains=["betking.com"],
        common_typos=["bet-king", "betkingng"],
        description="BetKing Nigeria",
    ),
]

# ── BUILD MASTER REGISTRY ────────────────────────────────────────────────────

ALL_BRANDS: List[NigerianBrand] = BANKS + FINTECHS + GOVERNMENT + TELECOMS + ECOMMERCE + BETTING

# Fast lookup: domain -> brand
OFFICIAL_DOMAIN_MAP: Dict[str, NigerianBrand] = {}
for brand in ALL_BRANDS:
    for domain in brand.official_domains:
        OFFICIAL_DOMAIN_MAP[domain.lower()] = brand


def lookup_domain(domain: str) -> Optional[NigerianBrand]:
    """
    Check if a domain is a known official Nigerian brand domain.
    Returns the brand if found, else None.
    """
    return OFFICIAL_DOMAIN_MAP.get(domain.lower())


def find_impersonated_brand(domain: str) -> Optional[NigerianBrand]:
    """
    Check if a domain looks like an impersonation of a known Nigerian brand.
    Returns the impersonated brand if detected.
    """
    domain_l = domain.lower()
    # Remove TLD for fuzzy matching
    domain_base = domain_l.split(".")[0] if "." in domain_l else domain_l

    for brand in ALL_BRANDS:
        # Skip if it's an exact official domain
        if brand.is_official(domain_l):
            return None

        # Check common typos list
        for typo in brand.common_typos:
            if typo in domain_l:
                return brand

        # Check if brand keywords appear in domain (not official)
        brand_keywords = [
            kw for kw in brand.name.lower().split() if len(kw) > 3
        ]
        for kw in brand_keywords:
            if kw in domain_base and not brand.is_official(domain_l):
                # Only flag if it's a suspicious match (has extra chars or different TLD)
                for off_d in brand.official_domains:
                    off_base = off_d.split(".")[0]
                    if kw in domain_base and domain_base != off_base:
                        return brand

    return None


# Known scam keyword patterns commonly found in Nigerian phishing URLs
SCAM_URL_PATTERNS = [
    r"verify.*account",
    r"account.*verify",
    r"update.*bank",
    r"bank.*update",
    r"bvn.*verify",
    r"bvn.*update",
    r"nin.*verify",
    r"login.*secure",
    r"secure.*login",
    r"confirm.*transfer",
    r"alert.*payment",
    r"reward.*claim",
    r"claim.*reward",
    r"free.*airtime",
    r"airtime.*free",
    r"palmpay.*bonus",
    r"opay.*promo",
    r"cbn.*portal",
    r"central.*bank.*portal",
    r"efcc.*arrest",
    r"police.*warrant",
    r"\d{10,}.*verification",
    r"investment.*daily.*profit",
    r"double.*your.*money",
    r"bitcoin.*investment.*nigeria",
    r"forex.*profit.*guaranteed",
    r"play.*earn.*nigeria",
    r"ponzi.*scheme",
    r"mmo.*crypto",
]

# Known Nigerian scam domain suffixes/patterns
SCAM_DOMAIN_PATTERNS = [
    r"ng-verify",
    r"nigeria-claim",
    r"naija-free",
    r"verify-ng",
    r"bank-ng-",
    r"nigeria-bank",
    r"-promo-ng",
    r"mtn-free",
    r"airtel-promo",
    r"glo-free",
    r"cbn-reward",
    r"nin-portal-",
    r"jamb-portal-",
]

# Suspicious TLDs often used in Nigerian phishing (not inherently bad, but worth flagging)
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".loan", ".gq", ".ml", ".cf", ".tk",
    ".work", ".fun", ".online", ".site", ".space", ".pw", ".cc",
    ".icu", ".rest", ".live", ".vip", ".win", ".bid", ".trade",
}

# Known URL shorteners
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rb.gy", "cutt.ly", "tiny.cc", "is.gd", "v.gd",
    "shorte.st", "adf.ly", "linktr.ee", "lnkd.in", "wa.me", "wa.link",
}
