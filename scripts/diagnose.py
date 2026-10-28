import pandas as pd
import numpy as np
import os

BASE = os.path.dirname(os.path.abspath(__file__))

df_train = pd.read_csv(f'{BASE}/datasets/processed/bert_train_v2.csv')
df_val   = pd.read_csv(f'{BASE}/datasets/processed/bert_val_v2.csv')
df_test  = pd.read_csv(f'{BASE}/datasets/processed/bert_test_v2.csv')

label_names = {0: 'BENIGN', 1: 'SQLi', 2: 'XSS'}

print("="*60)
print("DATASET SIZES")
print("="*60)
print(f"Train: {len(df_train)}")
print(f"Val:   {len(df_val)}")
print(f"Test:  {len(df_test)}")

print("\n" + "="*60)
print("CLASS DISTRIBUTION")
print("="*60)
for split_name, df in [('Train', df_train), ('Val', df_val), ('Test', df_test)]:
    print(f"\n{split_name}:")
    for k, v in df['label'].value_counts().sort_index().items():
        pct = v / len(df) * 100
        print(f"  {label_names[k]:8} ({k}): {v:6} ({pct:.1f}%)")

print("\n" + "="*60)
print("TEXT LENGTH DISTRIBUTION (characters)")
print("="*60)
df_train['text_len'] = df_train['text'].str.len()
for label_id in [0, 1, 2]:
    subset = df_train[df_train['label'] == label_id]['text_len']
    print(f"\n{label_names[label_id]}:")
    print(f"  min:    {subset.min():.0f}")
    print(f"  median: {subset.median():.0f}")
    print(f"  max:    {subset.max():.0f}")
    print(f"  mean:   {subset.mean():.0f}")

print("\n" + "="*60)
print("LINE COUNT DISTRIBUTION")
print("="*60)
df_train['line_count'] = df_train['text'].str.count('\n') + 1
for label_id in [0, 1, 2]:
    subset = df_train[df_train['label'] == label_id]['line_count']
    print(f"\n{label_names[label_id]}:")
    print(f"  min:    {subset.min():.0f}")
    print(f"  median: {subset.median():.0f}")
    print(f"  max:    {subset.max():.0f}")

print("\n" + "="*60)
print("HTTP METHOD DISTRIBUTION")
print("="*60)
df_train['method'] = df_train['text'].str.extract(r'^(GET|POST|PUT|DELETE|HEAD|PATCH)')
for label_id in [0, 1, 2]:
    subset = df_train[df_train['label'] == label_id]['method'].value_counts()
    print(f"\n{label_names[label_id]}:")
    print(subset.to_string())

print("\n" + "="*60)
print("SAMPLE BENIGN RECORDS (train)")
print("="*60)
benign_samples = df_train[df_train['label'] == 0]['text'].head(3)
for i, s in enumerate(benign_samples):
    print(f"\nBENIGN sample {i+1}:")
    print(s[:300])
    print("---")

print("\n" + "="*60)
print("SAMPLE SQLi RECORDS (train)")
print("="*60)
sqli_samples = df_train[df_train['label'] == 1]['text'].head(3)
for i, s in enumerate(sqli_samples):
    print(f"\nSQLi sample {i+1}:")
    print(s[:300])
    print("---")

print("\n" + "="*60)
print("SAMPLE XSS RECORDS (train)")
print("="*60)
xss_samples = df_train[df_train['label'] == 2]['text'].head(3)
for i, s in enumerate(xss_samples):
    print(f"\nXSS sample {i+1}:")
    print(s[:300])
    print("---")

print("\n" + "="*60)
print("PAYLOAD OVERLAP CHECK (train vs test)")
print("="*60)
train_texts = set(df_train['text'].tolist())
test_texts  = set(df_test['text'].tolist())
overlap     = train_texts.intersection(test_texts)
print(f"Exact duplicates between train and test: {len(overlap)}")

print("\n" + "="*60)
print("TOKENIZER CHECK")
print("="*60)
import json
tok_config_path = f'{BASE}/models/bert/tokenizer/tokenizer_config.json'
if os.path.exists(tok_config_path):
    with open(tok_config_path) as f:
        tok_config = json.load(f)
    print(f"Tokenizer type: {tok_config.get('tokenizer_class', 'unknown')}")
    print(f"Model max length: {tok_config.get('model_max_length', 'unknown')}")
else:
    print("tokenizer_config.json not found")

print("\n" + "="*60)
print("PREPROCESSING CHECK")
print("="*60)
sample_benign = df_train[df_train['label'] == 0]['text'].iloc[0]
print("First benign record starts with:")
print(repr(sample_benign[:100]))
print(f"\nContains URL encoding (%XX): {'%' in sample_benign}")
print(f"Contains HTML entities (&lt;): {'&lt;' in sample_benign or '&amp;' in sample_benign}")