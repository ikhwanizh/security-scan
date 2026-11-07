import pickle

import joblib
import torch


def load(model_path, data):
    with open(model_path, "rb") as f:
        # ruleid: kscan-unsafe-deserialization
        topic_model = pickle.load(f)
    # ruleid: kscan-unsafe-deserialization
    obj = pickle.loads(data)
    # ruleid: kscan-unsafe-deserialization
    clf = joblib.load(model_path)
    # ruleid: kscan-unsafe-deserialization
    w = torch.load(model_path)
    # ok: kscan-unsafe-deserialization
    w2 = torch.load(model_path, weights_only=True)
    # ok: kscan-unsafe-deserialization
    raw = pickle.dumps(obj)
    return topic_model, clf, w, w2, raw
