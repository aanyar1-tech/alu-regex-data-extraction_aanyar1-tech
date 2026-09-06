import json
import re
from pathlib import Path


def luhn_check(card_number: str) -> bool:
    digits = [int(d) for d in re.sub(r'\D', '', card_number)]
    if not digits or not (13 <= len(digits) <= 19):
        return False

    checksum = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def mask_credit_card(card_number: str) -> str:
    clean_digits = re.sub(r'\D', '', card_number)
    if len(clean_digits) < 8:
        return "XXXX-XXXX-XXXX"
    return f"{clean_digits[:4]}-XXXX-XXXX-{clean_digits[-4:]}"


def mask_email(email: str) -> str:
    try:
        local_part, domain = email.split('@', 1)
        if len(local_part) <= 2:
            masked_local = local_part[0] + "*"
        else:
            masked_local = local_part[0] + "*" * (len(local_part) - 2) + local_part[-1]
        return f"{masked_local}@{domain}"
    except ValueError:
        return "****@****.***"


class DataExtractorValidator:
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b')
    ALU_OFFICIAL_PATTERN = re.compile(r'^[a-z0-9._%+-]+@alueducation\.com$')
    ALU_ALUMNI_PATTERN = re.compile(r'^[a-z0-9._%+-]+@alumni\.alueducation\.com$')
    ALU_SI_PATTERN = re.compile(r'^[a-z0-9._%+-]+@si\.alueducation\.com$')
    CARD_PATTERN = re.compile(
        r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|(?:[0-9]{4}[- ]){3}[0-9]{4})\b'
    )
    URL_PATTERN = re.compile(
        r'\bhttps?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}(?::\d{1,5})?(?:/[^\s<>'"\\]*)?'
    )
    RWANDA_PHONE_PATTERN = re.compile(
        r'(?:\+?250|00250|0)?[\s.-]?(7[2389]\d)[\s.-]?(\d{3})[\s.-]?(\d{3})\b'
    )

    def __init__(self, raw_text: str):
        sanitized_text = raw_text.replace('\x00', '')
        self.raw_text = re.sub(r'[\u200B-\u200D\u202A-\u202E]', '', sanitized_text)
        self.audit_log = []

    def extract_emails(self) -> dict:
        candidates = self.EMAIL_PATTERN.findall(self.raw_text)
        directories = {
            "alu_official": [],
            "alu_alumni": [],
            "alu_si": [],
            "general_external": []
        }

        for email in set(candidates):
            email_lower = email.lower()
            if ".." in email_lower:
                self.audit_log.append({"input": email, "status": "REJECTED", "reason": "Malformed email (double dot)"})
                continue
            if "alueducation" in email_lower and not email_lower.endswith("alueducation.com"):
                self.audit_log.append({"input": email, "status": "REJECTED", "reason": "Potential domain spoofing"})
                continue

            masked_address = mask_email(email_lower)
            if self.ALU_OFFICIAL_PATTERN.match(email_lower):
                directories["alu_official"].append(masked_address)
            elif self.ALU_ALUMNI_PATTERN.match(email_lower):
                directories["alu_alumni"].append(masked_address)
            elif self.ALU_SI_PATTERN.match(email_lower):
                directories["alu_si"].append(masked_address)
            else:
                directories["general_external"].append(masked_address)

        for key in directories:
            directories[key] = sorted(directories[key])
        return directories

    def extract_credit_cards(self) -> list:
        candidates = self.CARD_PATTERN.findall(self.raw_text)
        valid_cards = []
        for card in set(candidates):
            if luhn_check(card):
                valid_cards.append(mask_credit_card(card))
            else:
                self.audit_log.append({"input": mask_credit_card(card), "status": "REJECTED", "reason": "Failed Luhn checksum"})
        return sorted(valid_cards)

    def extract_urls(self) -> list:
        candidates = self.URL_PATTERN.findall(self.raw_text)
        valid_urls = []
        for url in set(candidates):
            cleaned_url = url.rstrip(".,;)")
            url_lower = cleaned_url.lower()
            if any(vector in url_lower for vector in ["<script", "javascript:", "%3cscript"]):
                self.audit_log.append({"input": cleaned_url, "status": "REJECTED", "reason": "Possible XSS vector in URL"})
                continue
            valid_urls.append(cleaned_url)
        return sorted(valid_urls)

    def extract_phone_numbers(self) -> list:
        matches = self.RWANDA_PHONE_PATTERN.finditer(self.raw_text)
        valid_phones = set()
        for match in matches:
            prefix, mid, last = match.group(1), match.group(2), match.group(3)
            digits_only = f"250{prefix}{mid}{last}"
            if len(set(digits_only)) <= 2:
                self.audit_log.append({"input": digits_only, "status": "REJECTED", "reason": "Trivial/repeated dummy phone number"})
                continue
            formatted = f"+250 {prefix} {mid} {last}"
            valid_phones.add(formatted)
        return sorted(list(valid_phones))

    def process(self) -> dict:
        return {
            "validation_summary": {
                "total_rejected_inputs": len(self.audit_log),
                "rejection_details": self.audit_log
            },
            "extracted_data": {
                "emails": self.extract_emails(),
                "credit_cards": self.extract_credit_cards(),
                "urls": self.extract_urls(),
                "phone_numbers": self.extract_phone_numbers()
            }
        }


def main():
    base_dir = Path(__file__).resolve().parent.parent
    input_file = base_dir / "input" / "raw-text.txt"
    output_file = base_dir / "output" / "sample-output.json"

    if not input_file.exists():
        print(f"Error: Input file not found at {input_file}")
        return

    raw_content = input_file.read_text(encoding="utf-8")
    extractor = DataExtractorValidator(raw_content)
    results = extractor.process()

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("==================================================")
    print("      DATA EXTRACTION & VALIDATION SUMMARY        ")
    print("==================================================")
    print(f"Processed Input File : {input_file.name}")
    print(f"Total Inputs Rejected: {results['validation_summary']['total_rejected_inputs']}")
    print("--------------------------------------------------")
    print(f"ALU Official Emails  : {len(results['extracted_data']['emails']['alu_official'])}")
    print(f"ALU Alumni Emails    : {len(results['extracted_data']['emails']['alu_alumni'])}")
    print(f"ALU SI Emails        : {len(results['extracted_data']['emails']['alu_si'])}")
    print(f"External Emails      : {len(results['extracted_data']['emails']['general_external'])}")
    print(f"Valid Credit Cards   : {len(results['extracted_data']['credit_cards'])}")
    print(f"Verified Web URLs    : {len(results['extracted_data']['urls'])}")
    print(f"Rwandan Phone Lines  : {len(results['extracted_data']['phone_numbers'])}")
    print("==================================================")
    print(f"Results saved to     : {output_file}")


if __name__ == "__main__":
    main()
