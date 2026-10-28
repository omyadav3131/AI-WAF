import streamlit as st
import requests
import matplotlib.pyplot as plt
import numpy as np

API_URL = 'http://localhost:8000'

st.set_page_config(page_title='AI-WAF Dashboard', page_icon='🛡️', layout='wide')
st.title('AI-WAF — Web Attack Detection System')
st.markdown('Classify HTTP requests as **BENIGN**, **SQL Injection**, or **XSS** using fine-tuned BERT v3.')

with st.sidebar:
    st.header('Model Info')
    st.markdown('''
**Model:** bert-base-uncased v3
**Val Macro F1:** 0.9994
**Test Macro F1:** 0.9993
**Manual tests:** 18/18 passed

**v3 fixes:**
- Paired benign/attack templates
- Matched request lengths
- Adversarial benign samples
- False positive rate fixed
    ''')
    st.header('Sample Requests')
    if st.button('Load SQLi Sample'):
        st.session_state['sample'] = "GET /search?q=' OR 1=1-- HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0"
    if st.button('Load XSS Sample'):
        st.session_state['sample'] = "POST /comment HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nbody=<script>alert(document.cookie)</script>"
    if st.button('Load Benign Sample'):
        st.session_state['sample'] = "GET /products?category=electronics&page=2 HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: text/html"
    if st.button('Load Adversarial Benign'):
        st.session_state['sample'] = "GET /search?q=select+shoes HTTP/1.1\nHost: example.com"

default = st.session_state.get('sample',
    "GET /products?category=electronics&page=2 HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0\nAccept: text/html")

st.subheader('HTTP Request Input')
request_text = st.text_area('Paste an HTTP request:', value=default, height=160)

col1, col2 = st.columns([1, 5])
with col1:
    analyze = st.button('Analyze', type='primary', use_container_width=True)
with col2:
    if st.button('Clear'):
        st.session_state['sample'] = ''
        st.rerun()

if analyze and request_text.strip():
    with st.spinner('Classifying...'):
        try:
            resp   = requests.post(f'{API_URL}/predict',
                                   json={'request': request_text}, timeout=60)
            result = resp.json()
        except requests.exceptions.ConnectionError:
            st.error('Cannot connect to API at localhost:8000. Start FastAPI in another terminal first.')
            st.stop()
        except Exception as e:
            st.error(f'API error: {e}')
            st.stop()

    st.divider()
    label = result['label']
    conf  = result['confidence']

    if label == 'BENIGN':
        st.success(f'BENIGN — Confidence: {conf:.1%}')
    else:
        st.error(f'ATTACK DETECTED: {label} — Confidence: {conf:.1%}')

    col_a, col_b, col_c = st.columns(3)
    col_a.metric('Prediction', label)
    col_b.metric('Confidence', f'{conf:.1%}')
    col_c.metric('Class ID',   result['class_id'])

    st.subheader('Class Probabilities')
    probs       = result['probs']
    class_names = ['BENIGN', 'SQL Injection', 'XSS']
    colors      = ['#2ecc71' if c == label else '#95a5a6' for c in class_names]
    fig1, ax1   = plt.subplots(figsize=(7, 2.5))
    bars        = ax1.barh(class_names, probs, color=colors)
    ax1.set_xlim(0, 1.1)
    ax1.set_xlabel('Probability')
    for bar, prob in zip(bars, probs):
        ax1.text(prob + 0.01, bar.get_y() + bar.get_height()/2,
                 f'{prob:.4f}', va='center', fontsize=10)
    plt.tight_layout()
    st.pyplot(fig1)
    plt.close()

    st.subheader('Token Attention Heatmap')
    tokens  = result['tokens']
    attn    = result['attention_weights']
    display = [(t, a) for t, a in zip(tokens, attn)
               if t not in ['[CLS]', '[SEP]', '[PAD]']][:40]
    if display:
        d_toks = [t for t, _ in display]
        d_attn = [a for _, a in display]
        fig2, ax2 = plt.subplots(figsize=(max(10, len(d_toks)*0.5), 2.5))
        im = ax2.imshow(np.array(d_attn).reshape(1,-1),
                        cmap='YlOrRd', aspect='auto', vmin=0, vmax=1)
        ax2.set_xticks(range(len(d_toks)))
        ax2.set_xticklabels(d_toks, rotation=45, ha='right', fontsize=9)
        ax2.set_yticks([])
        ax2.set_title('Darker = higher attention weight')
        plt.colorbar(im, ax=ax2, orientation='horizontal', fraction=0.05, pad=0.5)
        plt.tight_layout()
        st.pyplot(fig2)
        plt.close()

    st.caption('Attention weights are an interpretability aid — not causal proof of classification decision.')

elif analyze:
    st.warning('Please enter an HTTP request.')