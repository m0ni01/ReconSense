import google.generativeai as genai

genai.configure(api_key="AIzaSyAcnP2ggQFQMGZe8WwZsGdk4ckGwc05RL0")

# Example of listing models with the native library
for m in genai.list_models():
  if 'generateContent' in m.supported_generation_methods:
    print(m.name)