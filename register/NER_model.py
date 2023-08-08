import pprint
import re
import spacy
from datetime import datetime
import nltk
from geopy.geocoders import Nominatim
from spacy.matcher import Matcher
from .Resume_to_text import convert_to_text
import json

class ResumeExtractor:
    def __init__(self):
        pass

    def extract_name(self, text):
        nlp = spacy.load("en_core_web_sm")
        doc = nlp(text)
        name = None

        for entity in doc.ents:
            if entity.label_ == "PERSON":
                name = entity.text
                break

        return name

    def extract_email(self, text):
        email = None
        pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        matches = re.findall(pattern, text)
        if matches:
            email = matches[0]
        return email

    def extract_mobile_number(self, text):
        mobile_regex = r'\b(?:\+?\d{1,3}[-.●]?)?\(?\d{3}\)?[-.●]?\d{3}[-.●]?\d{4}\b'
        numbers = re.findall(mobile_regex, text)
        if numbers:
            return numbers[0]
        else:
            return None
        
    def extract_dob(self, text):
        nlp = spacy.load('en_core_web_sm')
        doc = nlp(text)

        dob_text_1 = None
        dob_text_2 = None

        # Pattern 1: dd-of-(DATE)-dd-of-(DATE)-dddd
        pattern1 = [
            {'SHAPE': 'dd'},
            {'LOWER': 'of'},
            {'ENT_TYPE': 'DATE', 'OP': '?'},
            {'LOWER': {'IN': ['-', '/', '.']}},
            {'SHAPE': 'dd'},
            {'LOWER': 'of'},
            {'ENT_TYPE': 'DATE', 'OP': '?'},
            {'LOWER': {'IN': ['-', '/', '.']}},
            {'SHAPE': 'dddd'}
        ]

        matcher1 = Matcher(nlp.vocab)
        matcher1.add('DOB1', [pattern1])
        matches1 = matcher1(doc)

        for _, start, end in matches1:
            dob_text_1 = doc[start:end].text

        # Pattern 2: date-of-birth-(dd/dd/dddd)
        pattern2 = [
            {'LOWER': 'date'},
            {'LOWER': 'of'},
            {'LOWER': 'birth'},
            {'OP': '?'},
            {'SHAPE': 'dd/dd/dddd'}
        ]

        matcher2 = Matcher(nlp.vocab)
        matcher2.add('DOB2', [pattern2])
        matches2 = matcher2(doc)

        for _, start, end in matches2:
            dob_text_2 = doc[start:end].text

        if dob_text_1 is not None:
            dob_text = dob_text_1
        else:
            dob_text = dob_text_2

        return dob_text
    
    def calculate_age(self, text):
        dob_text = self.extract_dob(text)
        if dob_text is not None:
            current_date = datetime.now()
            dob = datetime.strptime(dob_text, '%d/%m/%Y')
            age = current_date.year - dob.year

            if current_date.month < dob.month or (current_date.month == dob.month and current_date.day < dob.day):
                age -= 1

            return age
        else:
            return None

    def extract_personal_address(self, text):
        address_regex = r'\b(\d+\s+[\w\s]+,\s+[\w\s]+,\s+[\w\s]+)\b'
        addresses = re.findall(address_regex, text)
        if addresses:
            return addresses[0]
        else:
            return None

    def extract_postal_code(self, text):
        pattern = r"\bCA\s+(\d{5})\b"
        match = re.search(pattern, text)
        if match:
            return match.group(1)
        else:
            return None

    def extract_city(self, text):
        pattern = r"\b(\d{5})\b"
        match = re.search(pattern, text)
        if match:
            zip_code = match.group(1)
            geolocator = Nominatim(user_agent="my_application")
            location = geolocator.geocode({"postalcode": zip_code}, addressdetails=True)
            if location is not None:
                city = location.raw["address"]["city"]
                return city
        return None

    def extract_country_code(self, text):
        pattern = r"\bCountry:\s*([A-Za-z]{2})"
        match = re.search(pattern, text)
        if match:
            return match.group(1)
        else:
            return None

    def extract_educational_location(self, text):
        location_regex = r"\b(?:studied|in|at|from)\s+([\w\s]+(?:,\s+[\w\s]+)*)\b"
        matches = re.findall(location_regex, text, re.IGNORECASE)
        if matches:
            return matches
        else:
            return None

    def extract_educational_subject(self, text):
        pattern = r"(?i)(Bachelor of\s[\w\s]+|Master of\s[\w\s]+|PG Diploma in\s[\w\s]+)"
        match = re.search(pattern, text)
        if match:
            subject = re.sub(r'\n.*', '', match.group(0)).strip()
            return subject
        else:
            return None

    def extract_educational_institution(self, text):
        nlp = spacy.load('en_core_web_sm')
        doc = nlp(text)
        institutions = []
        keywords = ['university', 'school', 'college']

        for entity in doc.ents:
            if entity.label_ == "ORG":
                university = entity.text.lower()
                for keyword in keywords:
                    if keyword in university:
                        institutions.append(university)
                        break

        if institutions:
            return institutions
        else:
            return None

    def extract_start_year(self, text):
        start_year_regex = r"\b(?:from|since|in)\s+(\d{4})\b"
        matches = re.findall(start_year_regex, text, re.IGNORECASE)
        if matches:
            return [int(match) for match in matches]
        else:
            return None

    def extract_end_year(self, text):
        end_year_regex = r"\b(?:to|till|until)\s+(\d{4})\b"
        matches = re.findall(end_year_regex, text, re.IGNORECASE)
        if matches:
            return [int(match) for match in matches]
        else:
            return None

    def extract_grade_score(self, text):
        grade_regex = r"(?i)\b(?:gpa|grade|score)\s+([\d.]+)\b"
        matches = re.findall(grade_regex, text)
        if matches:
            return [float(match) for match in matches]
        else:
            return None

    def extract_english_speaking(self, text):
        english_speaking_regex = r"(?i)\b(?:english|fluent)\s*(?:speaking|spoken)\b"
        return "Yes" if re.search(english_speaking_regex, text) else "No"

    def extract_english_writing(self, text):
        english_writing_regex = r"(?i)\b(?:english|fluent)\s*(?:writing|written)\b"
        return "Yes" if re.search(english_writing_regex, text) else "No"

    def extract_leadership(self, text):
        leadership_keywords = ['leader', 'manager', 'supervisor']
        tokenized_text = nltk.word_tokenize(text.lower())
        pos_tags = nltk.pos_tag(tokenized_text)

        for word, pos in pos_tags:
            if pos.startswith('NN') and word in leadership_keywords:
                return "Yes"

        return "No"


    def extract_tech_skills(self, text):
        nlp = spacy.load('en_core_web_sm')
        doc = nlp(text)
        skills = []
        tech_keywords = ["python", "java", "c++", "javascript", 'machine', 'django', 'ann', 'html5']

        for token in doc:
            if token.text.lower() in tech_keywords:
                skills.append(token.text)

        if skills:
            return list(set(skills))
        else:
            return None

    def extract_interests(self, text):
        word_list = ["Reading", "Travelling", 'Dance', 'Music']
        pattern = r"\b(?:{})\b".format("|".join(word_list))
        matches = re.findall(pattern, text, re.IGNORECASE)

        if matches:
            return matches
        else:
            return None

    def extract_work_name(self, text):
        work_name_regex = r"\b(?:work|experience)\b:\s*(.+)"
        match = re.search(work_name_regex, text, re.IGNORECASE)
        if match:
            work_name = match.group(1)
            return work_name.strip()
        else:
            return None

    def extract_work_position(self, text):
        position_regex = r"\b(?:position|role)\b:\s*(.+)"
        match = re.search(position_regex, text, re.IGNORECASE)
        if match:
            position = match.group(1)
            return position.strip()
        else:
            return None

    def extract_work_start_date(self, text):
        date_regex = r"\b(?:start|begin)\s+date\b:\s*(\d{4})"
        match = re.search(date_regex, text, re.IGNORECASE)
        if match:
            start_date = match.group(1)
            return start_date.strip()
        else:
            return None

    def extract_work_end_date(self, text):
        date_regex = r"\bend\s+date\b:\s*(\d{4})"
        matches = re.findall(date_regex, text, re.IGNORECASE)
        if matches:
            end_dates = [match for match in matches]
            return end_dates[-1].strip()
        else:
            return None

    def extract_certificate_name(self, text):
        name_regex = r"\bcertificate\b:\s*(.+)"
        match = re.search(name_regex, text, re.IGNORECASE)
        if match:
            name = match.group(1)
            return name.strip()
        else:
            return None

    def extract_certificate_date(self, text):
        date_regex = r"\bdate\b:\s*(\d{4})"
        matches = re.findall(date_regex, text, re.IGNORECASE)
        if matches:
            dates = [match for match in matches]
            return dates[-1].strip()
        else:
            return None

    def extract_certificate_issuer(self, text):
        issuer_regex = r"\b(?:issued\s+by|certified\s+by|awarded\s+by)\b:\s*(.+)"
        match = re.search(issuer_regex, text, re.IGNORECASE)
        if match:
            issuer = match.group(1)
            return issuer.strip()
        else:
            return None

    def extract_project_name(self, text):
        name_regex = r"\b(?:project|assignment)\b\s*:\s*(.+)"
        match = re.search(name_regex, text, re.IGNORECASE)
        if match:
            name = match.group(1)
            return name.strip()
        else:
            return None

    def extract_project_description(self, text):
        description_regex = r"\bdescription\b\s*:\s*(.+)"
        match = re.search(description_regex, text, re.IGNORECASE)
        if match:
            description = match.group(1)
            return description.strip()
        else:
            return None

    def extract_project_role(self, text):
        nlp = spacy.load('en_core_web_sm')
        doc = nlp(text)
        role = []
        role_keywords = ['Team Lead', 'Manager', 'Associate', 'Developer', 'Software']

        for token in doc:
            if token.text.lower() in role_keywords:
                role.append(token.text.lower())

        role = list(set(role))

        if len(role) == 0:
            return None

        return role[0]
    
    def extract_study_type(self, text):
        study_type = []
        pattern = r"(?i)(?:\bBachelor\b.*?|\bB\.?\s*S\.?\b.*?)(\S+).*?(?:\bMaster\b.*?|\bM\.?\s*B\.?\s*A\b.*?)(\S+).*?(?:\bPG\b-?\s*Diploma\b.*?)(\S+)"
        matches = re.search(pattern, text)

        if matches:
            bachelor_degree = matches.group(1)
            master_degree = matches.group(2)
            study_type.extend(bachelor_degree)
            study_type.extend(master_degree)
        else:
            study_type = None
        return study_type
    
    def extract_education_start_date(self, text):
        start_date_regex = r"(?i)(?:start|begin|from)\s*date:?\s*(\d{1,2}/\d{1,2}/\d{4})"
        match = re.search(start_date_regex, text)
        if match:
            start_date_text = match.group(1)
            start_date = datetime.strptime(start_date_text, '%d/%m/%Y').date()
            return start_date
        else:
            return None

    def extract_education_end_date(self, text):
        end_date_regex = r"(?i)(?:end|finish|to)\s*date:?\s*(\d{1,2}/\d{1,2}/\d{4})"
        match = re.search(end_date_regex, text)
        if match:
            end_date_text = match.group(1)
            end_date = datetime.strptime(end_date_text, '%d/%m/%Y').date()
            return end_date
        else:
            return None

    
def data(file_path):
    try:
        txt = convert_to_text(file_path)
        extracted_data = {}
        resume_extractor = ResumeExtractor()

        extracted_data["Personal_info"] = {
            "Name": resume_extractor.extract_name(txt),
            "Age": resume_extractor.calculate_age(txt),
            "DOB": resume_extractor.extract_dob(txt),
            "Email": resume_extractor.extract_email(txt),
            "Phone": resume_extractor.extract_mobile_number(txt)
        }

        extracted_data["Location"] = {
            "Address": resume_extractor.extract_personal_address(txt),
            "PostalCode": resume_extractor.extract_postal_code(txt),
            "City": resume_extractor.extract_city(txt),
            "CountryCode": resume_extractor.extract_country_code(txt)
        }

        extracted_data["Education"] = {
            "Area": resume_extractor.extract_educational_subject(txt),
            "StudyType": resume_extractor.extract_study_type(txt),
            "Institution": resume_extractor.extract_educational_institution(txt),
            "StartDate": resume_extractor.extract_education_start_date(txt),
            "EndDate": resume_extractor.extract_education_end_date(txt),
            "Score": resume_extractor.extract_grade_score(txt)
        }

        extracted_data["Skills"] = {
            "Softskills": {
                "Englishspeaking": resume_extractor.extract_english_speaking(txt),
                "Englishwriting": resume_extractor.extract_english_writing(txt),
                "Leadership": resume_extractor.extract_leadership(txt)
            },
            "Techskills": resume_extractor.extract_tech_skills(txt)
        }

        extracted_data["Interests"] = resume_extractor.extract_interests(txt)

        extracted_data["Work"] = {
            "Name": resume_extractor.extract_work_name(txt),
            "Position": resume_extractor.extract_work_position(txt),
            "StartDate": resume_extractor.extract_work_start_date(txt),
            "EndDate": resume_extractor.extract_work_end_date(txt)
        }

        extracted_data["Certificates"] = {
            "Name": resume_extractor.extract_certificate_name(txt),
            "Date": resume_extractor.extract_certificate_date(txt),
            "Issuer": resume_extractor.extract_certificate_issuer(txt)
        }

        extracted_data["Projects"] = {
            "Name": resume_extractor.extract_project_name(txt),
            "Description": resume_extractor.extract_project_description(txt),
            "Role": resume_extractor.extract_project_role(txt)
        }

        # Convert the extracted data to JSON
        json_data = json.dumps(extracted_data, indent=4)  # Specify indent for pretty formatting
        return json_data
    except Exception as e:
        raise ImportError("Can't be imported. Error: " + str(e))

# data("C:\\Users\\nifun\\Downloads\\Resumes\\Blue Light Blue Color Blocks Physician CV.pdf")