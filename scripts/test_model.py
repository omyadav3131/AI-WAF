import torch
import torch.nn as nn
from transformers import AutoTokenizer, BertModel

MODEL = "models/bert/bert_best_v2.pt"
TOKENIZER = "models/bert/tokenizer"

tokenizer = AutoTokenizer.from_pretrained(TOKENIZER)

bert = BertModel.from_pretrained(
    "bert-base-uncased",
    attn_implementation="eager"
)

classifier = nn.Linear(768, 3)

checkpoint = torch.load(MODEL, map_location="cpu")

bert_state = {
    k.replace("bert.", "", 1): v
    for k, v in checkpoint.items()
    if k.startswith("bert.")
}

bert.load_state_dict(bert_state)

classifier.load_state_dict({
    "weight": checkpoint["classifier.weight"],
    "bias": checkpoint["classifier.bias"]
})

bert.eval()
classifier.eval()

tests = {
    "BENIGN": """GET /products?category=electronics&page=2 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: text/html""",

    "SQLi": """GET /products?id=1' OR '1'='1 HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0""",

    "XSS": """GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0"""
}

for expected, text in tests.items():

    encoding = tokenizer(
        text,
        max_length=128,
        padding="max_length",
        truncation=True,
        return_tensors="pt"
    )

    with torch.no_grad():

        output = bert(
            input_ids=encoding["input_ids"],
            attention_mask=encoding["attention_mask"]
        )

        logits = classifier(
            output.pooler_output
        )

        probs = torch.softmax(
            logits,
            dim=1
        )[0]

    pred = int(probs.argmax())

    labels = {
        0: "BENIGN",
        1: "SQLi",
        2: "XSS"
    }

    print("=" * 60)
    print("EXPECTED :", expected)
    print("PREDICTED:", labels[pred])
    print("BENIGN   :", round(float(probs[0]), 6))
    print("SQLi     :", round(float(probs[1]), 6))
    print("XSS      :", round(float(probs[2]), 6))

print("=" * 60)