import pytest
from app.mapping.cvss_calculator import cvss_calculator

@pytest.mark.parametrize("vector,expected_score,expected_band", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", 5.3, "Medium"), # Medium 5.3
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "Critical"), # Critical 9.8
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N", 2.2, "Low"), # Low 2.2
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0, "None"),
])
def test_cvss_calculator(vector, expected_score, expected_band):
    score, band = cvss_calculator.calculate(vector)
    assert score == expected_score
    assert band == expected_band

def test_cvss_boundary_cases():
    # 4.0 Medium
    score1, band1 = cvss_calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:L")
    assert score1 >= 4.0
    assert band1 == "Medium"

    # 7.0 High
    score2, band2 = cvss_calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L")
    assert score2 == 7.3 # example high
    assert band2 == "High"

    # 9.0 Critical
    score3, band3 = cvss_calculator.calculate("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L")
    assert score3 == 9.4
    assert band3 == "Critical"
