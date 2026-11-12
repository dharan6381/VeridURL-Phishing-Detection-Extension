# filename: api_server.py
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import pandas as pd
import xgboost as xgb
from extractor import URLFeatureExtractor

# Initialize FastAPI app
app = FastAPI(
    title="VeridURL API",
    description="Real-time Phishing Detection Backend with XGBoost ML Model",
    version="2.0.0"
)

# Enable CORS to allow extension popup and content script requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Robust pathing for model files
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
scaler_path = os.path.join(BASE_DIR, "ml_models", "scaler.pkl")
model_path = os.path.join(BASE_DIR, "ml_models", "xgboost_model.json")

if not os.path.exists(scaler_path) or not os.path.exists(model_path):
    raise FileNotFoundError(f"Model files not found in {os.path.join(BASE_DIR, 'ml_models')}. Please ensure scaler.pkl and xgboost_model.json are present.")

scaler = joblib.load(scaler_path)
booster = xgb.Booster()
booster.load_model(model_path)

# Expected features by the XGBoost booster
FEATURE_COLUMNS = [
    "URLLength", "DomainLength", "TLDLength", "NoOfImage", "NoOfJS", "NoOfCSS", 
    "NoOfSelfRef", "NoOfExternalRef", "IsHTTPS", "HasObfuscation", "HasTitle", 
    "HasDescription", "HasSubmitButton", "HasSocialNet", "HasFavicon", 
    "HasCopyrightInfo", "popUpWindow", "Iframe", "Abnormal_URL", 
    "LetterToDigitRatio", "Redirect_0", "Redirect_1"
]

class URLFeatures(BaseModel):
    URLLength: int
    DomainLength: int
    TLDLength: int
    NoOfImage: int
    NoOfJS: int
    NoOfCSS: int
    NoOfSelfRef: int
    NoOfExternalRef: int
    IsHTTPS: int
    HasObfuscation: int
    HasTitle: int
    HasDescription: int
    HasSubmitButton: int
    HasSocialNet: int
    HasFavicon: int
    HasCopyrightInfo: int
    popUpWindow: int
    Iframe: int
    Abnormal_URL: int
    LetterToDigitRatio: float
    Redirect_0: int
    Redirect_1: int

class URLInput(BaseModel):
    url: str

@app.post("/predict")
def predict(features: URLFeatures):
    """
    Direct endpoint for predicting phishing status from pre-extracted features.
    """
    try:
        input_df = pd.DataFrame([features.dict()], columns=FEATURE_COLUMNS)
        scaled_input = scaler.transform(input_df)
        dmatrix = xgb.DMatrix(scaled_input, feature_names=FEATURE_COLUMNS)
        
        pred = booster.predict(dmatrix)
        label = int(round(pred[0]))  # 1 = Legitimate, 0 = Phishing

        return {
            "prediction": label,
            "result": "Legitimate" if label == 1 else "Phishing",
            "score": float(pred[0])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/predict_url")
def predict_from_url(input_data: URLInput):
    """
    Main endpoint used by the extension.
    Fetches the URL, extracts its HTML and lexical features, and runs ML inference.
    """
    try:
        extractor = URLFeatureExtractor(input_data.url)
        features = extractor.extract_model_features()

        if "error" in features:
            return {"error": features["error"]}

        # Align extracted features into DataFrame
        input_df = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        scaled_input = scaler.transform(input_df)
        
        # XGBoost prediction
        dmatrix = xgb.DMatrix(scaled_input, feature_names=FEATURE_COLUMNS)
        pred = booster.predict(dmatrix)
        label = int(round(pred[0]))  # 1 = Legitimate, 0 = Phishing

        return {
            "features": features,
            "prediction": label,
            "result": "Legitimate" if label == 1 else "Phishing",
            "score": float(pred[0])
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "VeridURL API Server",
        "version": "2.0.0",
        "description": "Real-time Machine Learning Phishing Detection Engine"
    }
