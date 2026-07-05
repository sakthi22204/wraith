from cvss import CVSS3
from decimal import Decimal

class CVSSCalculator:
    @staticmethod
    def calculate(vector_string: str):
        try:
            c = CVSS3(vector_string)
            score = float(c.base_score)

            if score == 0:
                band = "None"
            elif 0.1 <= score <= 3.9:
                band = "Low"
            elif 4.0 <= score <= 6.9:
                band = "Medium"
            elif 7.0 <= score <= 8.9:
                band = "High"
            elif 9.0 <= score <= 10.0:
                band = "Critical"
            else:
                band = "Unknown"

            return score, band
        except Exception:
            return None, "Unknown"

cvss_calculator = CVSSCalculator()
