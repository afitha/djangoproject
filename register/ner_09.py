import spacy
nlp = spacy.load('en_core_web_lg')
import json
import os
import pandas as pd
from spacy.matcher import Matcher
# from datetime import datetime
import re
from geopy.geocoders import Nominatim
import pdfplumber
import datetime


class Resume_engineering():
    def __init__(self):
        pass
    
    def convert_text_to_text(self, file_path):
        extracted_text = ""
        with open(file_path, 'r') as file:
            text = file.read()
            extracted_text += text 
        return extracted_text
    
    def convert_pdf_to_text(self, file_path):
        with pdfplumber.open(file_path) as pdf:
            extracted_text = ""
            for page in pdf.pages:
                text = page.extract_text()
                extracted_text += text       
        return extracted_text
    
    def extract_file(self, file_path):
#         print(file_path)
        
        extracted_text = ""
        file_extension = os.path.splitext(file_path)[1]
        file_extension = file_extension[1:]
        if file_extension == 'pdf':
            extracted_text = self.convert_pdf_to_text(file_path)
        else:
            extracted_text = self.convert_text_to_text(file_path)
        return extracted_text
    
    def extract_email(self, resume_text):
        email = []
        pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
        matches = re.findall(pattern, resume_text)
        if matches:
            email_1 = matches[0]
            email.append(email_1)
        else:
            email = None
        return email
        
    def extract_entities(self, text):

        doc = nlp(text)
        for i in doc.ents:
            print(i, ':->', i.label_)
        
    def extract_name(self, resume_text):
#         print('Ent funct')

        doc = nlp(resume_text)
        name = []
        name_list = []
        for entity in doc.ents:
            if entity.label_ in ["PERSON"]:
                name_list.append((entity.label_, entity.text))
        if len(name_list) == 0:
            email = None 
        else:
            for item in name_list:
                name.extend(name_list)
        name = name[0]
        return name
    
    def extract_date_of_birth(self, resume_text):
        dob_text = []
        nlp = spacy.load("en_core_web_sm")

        matcher = Matcher(nlp.vocab)
        pattern = [
            {'LOWER': 'date'},
            {'LOWER': 'of'},
            {'LOWER': 'birth'},
            {'OP': '?'},
            {'SHAPE': 'dd/dd/dddd'}
        ]
        matcher.add('DOB', [pattern])

        doc = nlp(resume_text)
        matches = matcher(doc)

        for match_id, start, end in matches:
            dob_text.append(doc[start:end].text)

        if len(dob_text) == 0:
            dob_text = None

        return dob_text
    
    def extract_age(self, resume_text):
        resume_text= resume_text
#         dob = extract_date_of_birth(resume_text)
        dob_text = []
        nlp = spacy.load("en_core_web_sm")

        matcher = Matcher(nlp.vocab)
        pattern = [
            {'LOWER': 'date'},
            {'LOWER': 'of'},
            {'LOWER': 'birth'},
            {'OP': '?'},
            {'SHAPE': 'dd/dd/dddd'}
        ]
        matcher.add('DOB', [pattern])

        doc = nlp(resume_text)
        matches = matcher(doc)

        for match_id, start, end in matches:
            dob_text.append(doc[start:end].text)

        if len(dob_text) == 0:
            dob_text = None
        dob = dob_text

        if dob is not None:
            dob = dob[0].split(':')[1].strip()
            dob = datetime.datetime.strptime(dob, "%d/%m/%Y")
            current_date = datetime.datetime.now()
            age = current_date.year - dob.year

            if current_date.month < dob.month or (current_date.month == dob.month and current_date.day < dob.day):
                age -= 1
        else:
            age = None

        return age

    def extract_study_type(self, resume_text):
        study_type = []
        pattern = r"(?i)(?:\bBachelor\b.*?|\bB\.?\s*S\.?\b.*?)(\S+).*?(?:\bMaster\b.*?|\bM\.?\s*B\.?\s*A\b.*?)(\S+).*?(?:\bPG\b-?\s*Diploma\b.*?)(\S+)"
        matches = re.search(pattern, resume_text)

        if matches:
            bachelor_degree = matches.group(1)
            master_degree = matches.group(2)
            study_type.extend(bachelor_degree)
            study_type.extend(master_degree)
        else:
            study_type = None
        return study_type

    def extract_institution(self, resume_text):
        institution = []
        university = []
        nlp = spacy.load("en_core_web_lg")
        doc = nlp(resume_text)
        for entity in doc.ents:
            if entity.label_ in ["ORG"]:
                university.append(entity.text.lower())

        keywords = ['university', 'school', 'college']

        for sentence in university:
            for keyword in keywords:
                if keyword in sentence.lower():
                    institution.append(sentence)
                    break
        return institution

    def extract_address(self, resume_text):
        address_pattern = r"\b(\d+)\s+([A-Za-z]+\s+[A-Za-z]+)\s+(?:St(?:reet)?|Rd|Road|Blvd|Boulevard)\b"
        address = re.findall(address_pattern, resume_text)
        formatted_address = [f"{number} {street} {suffix}" for number, street, suffix in address]
        if len(formatted_address)==0:
            formatted_address=None   
        return(formatted_address)
    
    def extract_postal_code(self, resume_text):
        postal_code_pattern = r"\b([A-Za-z]{2})\s+(\d{5})\b"
        postal_codes = re.findall(postal_code_pattern, resume_text)
        formatted_postal_codes = [f"{state} {code}" for state, code in postal_codes]
        if len(formatted_postal_codes)==0:
            formatted_postal_codes=None  
        return formatted_postal_codes
    
    def extract_tech_skill(self, resume_text):
        skills = []
        nlp = spacy.load("en_core_web_lg")
        doc = nlp(resume_text)
        for token in doc:
            if token.text.lower() in ["python", "java", "c++", "javascript", 'machine', 'django', 'ann', 'html5']:
                skills.append(token.text)
                skills= list(set(skills))
                if len(skills) ==0:
                    skills = None
        return skills
    def extract_softskills(self, resume_text):
        nlp = spacy.load("en_core_web_lg")
        doc = nlp(resume_text)
        soft_skills = ["communication", "interpersonal", "motivation", "leadership"]
        language_skills = ["english", "spanish", "french", "german", "tamil", "malayalam", "hindi"]
        soft_skills = []
        for token in doc:
            token_text = token.text.lower()
            if token_text in soft_skills:
                soft_skills.append(token.text)
            if token_text in language_skills:
                soft_skills.append(token.text)
        if len(soft_skills)==0:
            soft_skills=None
        return soft_skills
    def extract_phone(self, resume_text):
        phone=[]
        mobile_regex = r'\b(?:\+?\d{1,3}[-.●]?)?\(?\d{3}\)?[-.●]?\d{3}[-.●]?\d{4}\b'
        numbers = re.findall(mobile_regex, resume_text)
        if numbers:
            phone.extend(numbers)
        else:
            phone= None
        return phone
    def extract_city(self, resume_text):
        
        city=[]
        zip_code=[]

        pattern = r"\b\d{5}\b"

        # Search for the pattern in the resume text
        matches = re.findall(pattern, resume_text)

        if matches:
            zip_code = matches[0]
            geolocator = Nominatim(user_agent="my_application")
            location = geolocator.geocode({"postalcode": zip_code}, addressdetails=True)
            if location is not None:
                city = location.raw["address"]["city"]
        return city
    def extract_country_code(self, resume_text):
        country_code=[]
        pattern = r"\bCountry:\s*([A-Za-z]{2})"

        # Search for the pattern in the resume text
        matches = re.search(pattern, resume_text)

        if matches:
            c_code = matches.group(1)
            country_code.append(c_code)
        else:
            country_code=None
        return country_code
    def extract_city(self, resume_text):
        city=[]
        zip_code=[]

        pattern = r"\b\d{5}\b"

        # Search for the pattern in the resume text
        matches = re.findall(pattern, resume_text)

        if matches:
            zip_code = matches[0]
        geolocator = Nominatim(user_agent="my_application")
        location = geolocator.geocode({"postalcode": zip_code}, addressdetails=True)
        if location is not None:
            city = location.raw["address"]["city"]
        return city
    def extract_interest(self, resume_text):
        interestes=[]
        interest = ["Reading", "Travelling", "Writing", "Cooking", "Sport", "Games"]
        interestes = [item for item in interest if item.lower() in resume_text.lower()]
        if len(interestes)==0:
            interestes= None
        return interestes
    def extract_position(self, resume_text):
        nlp = spacy.load("en_core_web_lg")
        doc = nlp(resume_text)
        role =[]
        word_list = ['Team Lead', 'Manager', 'associate', 'Developer', 'Software']
        word_list = [word.lower() for word in word_list]
        # print(word_list)

        for token in doc:
            if token.text.lower() in word_list:
                a=token.text
                role.append(a)
        

        role = [word.capitalize() for word in role]
        role  = list(set(role))
        if len(role)==0:
            role=None
        return role

resume_formatted_json={
      "Personal_info": {
          "name": "",
        "Age":"",
        "DOB": "",
          "email": "",
          "phone": ""
        },

       "location": {
          "address": "",
          "postalCode": "",
          "city": "",
          "countryCode": ""
        },

       "education":{
        "area": "",
          "studyType": "",
          "institution": "",
          "startDate": "",
          "endDate": "",
          "score": ""
           },

       "skills":{

           "Softskills":[{}],

        "Techskills":[{}]
            },

        "interests": [],

        "work": {
           "name": "",
           "position": "",
           "startDate": "",
           "endDate": ""
           },

       "certificates": [{
          "name": "",
          "date": "",
          "issuer": ""
          }],

      "projects": [{
            "name": "",
            "description": "",
            "role": ""
        }]

    }


# file_path = r"C:\Users\vijes\Desktop\data_science\intern_files\resume_extraction\new_files\Resume_Filtering-develop\Resume_Filtering-develop\Data\CVs\cv1"
# resume_text= ef.extract_file(file_path)
# print(resume_text)
# doc = nlp(resume_text)

def enter_skills(resume_text):
    ef =Resume_engineering()
    enter_tech_skill(resume_text)
    enter_softskills(resume_text)
    
def enter_tech_skill(resume_text):
    ef =Resume_engineering()
    tech_skills = ef.extract_tech_skill(resume_text)
    if tech_skills is not None:
        resume_formatted_json["skills"]["Techskills"] = [{skill: None} for skill in tech_skills]
def enter_softskills(resume_text):
    ef =Resume_engineering()
    soft_skills = ef.extract_softskills(resume_text)
    if soft_skills is not None:
        resume_formatted_json["skills"]["Techskills"] = [{skill: None} for skill in soft_skills]
def enter_personalinfo(resume_text):
#     print(resume_text)
    ef =Resume_engineering()
    name =ef.extract_name(resume_text)
    dob = ef.extract_date_of_birth(resume_text)
    age = ef.extract_age(resume_text)
    phone =ef.extract_phone(resume_text)
    email = ef.extract_email(resume_text)
    resume_formatted_json["Personal_info"]["name"] = name[1] if name is not None else None
    resume_formatted_json["Personal_info"]["Age"] = age if age is not None else None
    resume_formatted_json["Personal_info"]["DOB"] = dob if dob is not None else None
    resume_formatted_json["Personal_info"]["email"] = email if email is not None else None
    resume_formatted_json["Personal_info"]["phone"] = phone if phone is not None else None
def enter_location(resume_text):
    ef =Resume_engineering()
    address =ef.extract_address(resume_text)
    address = None
    postalCode=ef.extract_postal_code(resume_text)
    city =ef.extract_city(resume_text)
    countryCode=ef.extract_country_code(resume_text)
    
    resume_formatted_json["location"]["address"] = address if address is not None else None
    resume_formatted_json["location"]["postalCode"] = postalCode if postalCode is not None else None
    resume_formatted_json["location"]["city"] = city if city is not None else None
    resume_formatted_json["location"]["countryCode"] = countryCode if countryCode is not None else None

def enter_education(resume_text):
    ef =Resume_engineering()
    area =None
    studyType=ef.extract_study_type(resume_text)
    institution =ef.extract_institution(resume_text)
    startDate=None
    endDate=None
    score=None  
    resume_formatted_json["education"]["studyType"] = area if area is not None else None
    resume_formatted_json["education"]["postalCode"] = studyType if studyType is not None else None
    resume_formatted_json["education"]["institution"] = institution if institution is not None else None
    resume_formatted_json["education"]["startDate"] = startDate if startDate is not None else None  
    resume_formatted_json["education"]["endDate"] = endDate if endDate is not None else None
    resume_formatted_json["education"]["score"] = score if score is not None else None

def enter_interest(resume_text):
    ef =Resume_engineering()
    inter = ef.extract_interest(resume_text)
    resume_formatted_json["interests"] = inter

def enter_work(resume_text):
    ef =Resume_engineering()
    name_comp =None
    position=ef.extract_position(resume_text)
    startDate=None
    endDate=None
    resume_formatted_json["work"]["name"] = name_comp if name_comp is not None else None
    resume_formatted_json["work"]["position"] = position if position is not None else None
    resume_formatted_json["work"]["startDate"] = startDate if startDate is not None else None  
    resume_formatted_json["work"]["endDate"] = endDate if endDate is not None else None
def enter_certificate():
        resume_formatted_json["certificates"][0]["name"] = None
        resume_formatted_json["certificates"][0]["date"] = None
        resume_formatted_json["certificates"][0]["issuer"] = None
def enter_projects(resume_text):
    ef=Resume_engineering()
    role = ef.extract_position(resume_text)
    resume_formatted_json["projects"][0]["name"] = None
    resume_formatted_json["projects"][0]["description"] = None
    if role is not None:
        resume_formatted_json["projects"][0]["role"] = role
    else:
        resume_formatted_json["projects"][0]["role"] = None


# In[ ]:





# In[ ]:





# In[97]:


def create_json(file_path):
#     print(file_path)

    ef=Resume_engineering()
    resume_text= ef.extract_file(file_path)
#     print(resume_text)
    doc = nlp(resume_text)
    enter_personalinfo(resume_text)
#     for i in doc.ents:
#         print(i, ':->', i.label_)
    enter_location(resume_text)
    enter_education(resume_text)
    enter_skills(resume_text)
    enter_interest(resume_text)
    enter_work(resume_text)
    enter_certificate()
    enter_projects(resume_text)
    json_data = json.dumps(resume_formatted_json, indent=4)
    return json_data
    
    
    
    


# In[24]:





# In[98]:



# create_json(file_path)


# In[93]:


# # file_path = r"C:\Users\vijes\Desktop\data_science\intern_files\ner_resume_extraction\extracted_json"
# # f_name[0]= 

# filename = resume_formatted_json["Personal_info"]["name"][1].replace(' ', '_') + "_extracted_info.json"
# # print(filename)

# with open(file_path + filename, "w") as json_file:
#     json.dump(resume_formatted_json, json_file)


# In[94]:


# import pandas as pd

# # file_path = r"C:\Users\vijes\Desktop\data_science\intern_files\ner_resume_extraction\extracted_json"
# # f_name[0]= 

# filename = resume_formatted_json["Personal_info"]["name"][1].replace(' ', '_') + "_extracted_info.json"
# # print(filename)

# with open(file_path + filename, "w") as json_file:
#     data = json.load(file)
    


# In[ ]:




