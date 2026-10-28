import os
import re
import html
import urllib.parse

import torch
import torch.nn as nn

from transformers import AutoTokenizer, BertModel
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List

BASE       = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE, 'models', 'bert', 'bert_best_v3.pt')
TOK_PATH   = os.path.join(BASE, 'models', 'bert', 'tokenizer_v3')
DEVICE     = torch.device('cpu')
MAX_LEN    = 128
LABELS     = {0: 'BENIGN', 1: 'SQL Injection', 2: 'XSS'}

class AIWAFClassifier(nn.Module):
    def __init__(self, n_classes=3, dropout=0.1):
        super().__init__()
        self.bert       = BertModel.from_pretrained(
                            'bert-base-uncased',
                            attn_implementation='eager')
        self.dropout    = nn.Dropout(p=dropout)
        self.classifier = nn.Linear(768, n_classes)

    def forward(self, input_ids, attention_mask):
        outputs = self.bert(
            input_ids=input_ids,
            attention_mask=attention_mask,
            output_attentions=True
        )
        pooled  = outputs.pooler_output
        dropped = self.dropout(pooled)
        logits  = self.classifier(dropped)
        return logits, outputs.attentions

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(TOK_PATH, use_fast=True)

print("Loading BERT model...")
model = AIWAFClassifier().to(DEVICE)
checkpoint = torch.load(MODEL_PATH, map_location=DEVICE)
model.load_state_dict(checkpoint)
model.eval()
print(f"Model loaded. Device: {DEVICE}")

def preprocess(text: str) -> str:
    text = urllib.parse.unquote(text)
    text = html.unescape(text)
    text = text.replace('\r\n', '\n').replace('\r', '\n')
    text = re.sub(r'[ \t]+', ' ', text)
    return text.strip()

app = FastAPI(title='AI-WAF API', version='3.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_methods=['*'],
    allow_headers=['*'],
)

class HTTPRequest(BaseModel):
    request: str

class PredictionResponse(BaseModel):
    label:             str
    class_id:          int
    confidence:        float
    probs:             List[float]
    tokens:            List[str]
    attention_weights: List[float]

@app.get('/health')
def health():
    return {'status': 'running', 'version': 'v3', 'device': str(DEVICE)}

@app.post('/predict', response_model=PredictionResponse)
def predict(req: HTTPRequest):
    text     = preprocess(req.request)
    encoding = tokenizer(
        text,
        max_length=MAX_LEN,
        padding='max_length',
        truncation=True,
        return_tensors='pt'
    )
    input_ids      = encoding['input_ids'].to(DEVICE)
    attention_mask = encoding['attention_mask'].to(DEVICE)

    with torch.no_grad():
        logits, attentions = model(input_ids, attention_mask)

    probs      = torch.softmax(logits, dim=1).cpu().numpy()[0]
    pred_class = int(probs.argmax())
    confidence = float(probs[pred_class])

    last_layer = attentions[-1]
    avg_heads  = last_layer.mean(dim=1)
    cls_attn   = avg_heads[0, 0, :].cpu().numpy()
    tokens     = tokenizer.convert_ids_to_tokens(input_ids[0].cpu().numpy())
    real_len   = int(attention_mask[0].sum().item())
    tokens     = tokens[:real_len]
    cls_attn   = cls_attn[:real_len]

    mn, mx = cls_attn.min(), cls_attn.max()
    if mx > mn:
        cls_attn = (cls_attn - mn) / (mx - mn)

    return PredictionResponse(
        label             = LABELS[pred_class],
        class_id          = pred_class,
        confidence        = round(confidence, 4),
        probs             = [round(float(p), 4) for p in probs],
        tokens            = list(tokens),
        attention_weights = [round(float(a), 4) for a in cls_attn]
    )
