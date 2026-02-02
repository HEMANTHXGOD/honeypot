"""Intelligence extraction from scammer messages using regex."""

import re
from typing import Set
from models.session import Intelligence


# Regex patterns for intelligence extraction
PATTERNS = {
    "upi": r"[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}",
    "phone": r"(?:\+91[\s-]?)?[6-9]\d{9}|\b\d{10}\b",
    "bank_account": r"\b\d{9,18}\b",
    "url": r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
}

# Suspicious keywords to track
SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "blocked", "suspend", "kyc", "expire",
    "immediately", "account", "bank", "upi", "otp", "password",
    "transfer", "payment", "refund", "prize", "lottery", "winner",
    "click", "link", "confirm", "update", "action", "required"
]


class IntelligenceExtractor:
    """Extract scam intelligence from messages using regex patterns."""
    
    def extract_upi_ids(self, text: str) -> Set[str]:
        """Extract UPI IDs from text."""
        matches = re.findall(PATTERNS["upi"], text, re.IGNORECASE)
        # Filter out common email-like patterns that aren't UPI
        upi_ids = set()
        for match in matches:
            # UPI IDs typically have short provider names
            parts = match.split("@")
            if len(parts) == 2 and len(parts[1]) <= 10:
                upi_ids.add(match.lower())
        return upi_ids
    
    def extract_phone_numbers(self, text: str) -> Set[str]:
        """Extract Indian phone numbers from text."""
        matches = re.findall(PATTERNS["phone"], text)
        # Normalize phone numbers
        phones = set()
        for match in matches:
            # Remove spaces, dashes, and +91 prefix
            normalized = re.sub(r"[\s\-+]", "", match)
            if normalized.startswith("91"):
                normalized = normalized[2:]
            if len(normalized) == 10 and normalized[0] in "6789":
                phones.add(normalized)
        return phones
    
    def extract_bank_accounts(self, text: str) -> Set[str]:
        """Extract potential bank account numbers."""
        matches = re.findall(PATTERNS["bank_account"], text)
        # Filter out numbers that are likely not bank accounts
        accounts = set()
        for match in matches:
            # Bank accounts are typically 9-18 digits
            if 9 <= len(match) <= 18:
                # Avoid phone numbers (10 digits starting with 6-9)
                if len(match) == 10 and match[0] in "6789":
                    continue
                accounts.add(match)
        return accounts
    
    def extract_urls(self, text: str) -> Set[str]:
        """Extract URLs/phishing links from text."""
        matches = re.findall(PATTERNS["url"], text, re.IGNORECASE)
        return set(matches)
    
    def extract_keywords(self, text: str) -> Set[str]:
        """Extract suspicious keywords from text."""
        text_lower = text.lower()
        found = set()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                found.add(keyword)
        return found
    
    def extract_all(self, text: str, existing: Intelligence) -> Intelligence:
        """
        Extract all intelligence from text and merge with existing.
        
        Returns updated Intelligence object with deduplicated data.
        """
        # Extract new intelligence
        new_upi = self.extract_upi_ids(text)
        new_phones = self.extract_phone_numbers(text)
        new_accounts = self.extract_bank_accounts(text)
        new_urls = self.extract_urls(text)
        new_keywords = self.extract_keywords(text)
        
        # Merge with existing (deduplication via set operations)
        merged = Intelligence(
            upiIds=list(set(existing.upiIds) | new_upi),
            phoneNumbers=list(set(existing.phoneNumbers) | new_phones),
            bankAccounts=list(set(existing.bankAccounts) | new_accounts),
            phishingLinks=list(set(existing.phishingLinks) | new_urls),
            suspiciousKeywords=list(set(existing.suspiciousKeywords) | new_keywords)
        )
        
        return merged


# Global extractor instance
intelligence_extractor = IntelligenceExtractor()
