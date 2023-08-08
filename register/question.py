import json

# JSON data
json_data = '''{
  "Personal_info": {
    "name":"",
    "Age": "",
    "DOB": "19-11-1989",
    "email": "john@gmail.com",
    "phone": ""
  },
  "location": {
    "address": "21734 broadway st",
    "postalCode": "CA 94115",
    "city": "",
    "countryCode": "IN"
  },
  "education": {
    "area": "Software Development",
    "studyType": "Bachelor",
    "institution": "University",
    "startDate": "04-06-2009",
    "endDate": "03-05-2013",
    "score": "4.0"
  },
  "skills": {
    "Softskills": [
      {
        "Englishspeaking": "yes",
        "Englishwriting": "yes",
        "Leadership": "yes"
      }
    ],
    "Techskills": [
      {"python": "3"},
      {"Hadoop": "5"},
      {"HTML": "2"},
      {"Nodejs": "4"},
      {"Angular": "3"}
    ]
  },
  "interests": ["Reading", "Travelling"],
  "work": {
    "name": "Company",
    "position": "Developer",
    "startDate": "13-05-2014",
    "endDate": "20-05-2020"
  },
  "certificates": [
    {
      "name": "Experiencecertificate",
      "date": "06-07-2020",
      "issuer": "Company"
    }
  ],
  "projects": [
    {
      "name": "Project",
      "description": "Description…",
      "role": "Team Lead"
    }
  ]
}'''

# Parse JSON data
parsed_data = json.loads(json_data)

# Access specific values
name = parsed_data['Personal_info']['name']
education_area = parsed_data['education']['area']
skills = parsed_data['skills']

# Print values
print("Name:", name)
print("Education Area:", education_area)
print("Skills:", skills)
from transformers import T5ForConditionalGeneration,T5Tokenizer

question_model = T5ForConditionalGeneration.from_pretrained('ramsrigouthamg/t5_squad_v1')
question_tokenizer = T5Tokenizer.from_pretrained('t5-base')

def get_question(sentence,answer):
  text = "context: {} answer: {} </s>".format(sentence,answer)
  print (text)
  max_len = 256
  encoding = question_tokenizer.encode_plus(text,max_length=max_len, pad_to_max_length=True, return_tensors="pt")

  input_ids, attention_mask = encoding["input_ids"], encoding["attention_mask"]

  outs = question_model.generate(input_ids=input_ids,
                                  attention_mask=attention_mask,
                                  early_stopping=True,
                                  num_beams=5,
                                  num_return_sequences=1,
                                  no_repeat_ngram_size=2,
                                  max_length=200)


  dec = [question_tokenizer.decode(ids) for ids in outs]


  Question = dec[0].replace("question:","")
  Question= Question.strip()
  return Question



def check_missing_data(data, path, missing_fields):
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            if not value:
                missing_fields.append(current_path)
            check_missing_data(value, current_path, missing_fields)
    elif isinstance(data, list):
        for index, item in enumerate(data):
            current_path = f"{path}[{index}]"
            check_missing_data(item, current_path, missing_fields)

# JSON data
missing_fields = []
check_missing_data(parsed_data, "", missing_fields)

# Print missing fields, if any
if missing_fields:
    print("Missing data in fields:")
    for field in missing_fields:
#         print('This field is missing',field)
        dot_index = field.rfind('.')
        answer = field[dot_index + 1:].strip()
#         question = 'the number is' + answer\
        question = answer
           
        sentence_for_T5 = question.replace("**"," ")
        sentence_for_T5 = " ".join(sentence_for_T5.split())
#         print(field, answer)
#         answer =
        ques = get_question(sentence_for_T5,answer)
        print (ques, answer)


   
else:
    print("No missing data in fields.")