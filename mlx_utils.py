"""Thin wrappers over mlx-lm (tested against mlx-lm 0.32)."""
import mlx.core as mx
from mlx_lm import batch_generate, load
from mlx_lm.sample_utils import make_sampler

DEFAULT_MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"


def load_model(model=DEFAULT_MODEL, adapter=None):
    return load(model, adapter_path=adapter) if adapter else load(model)


def chat_ids(tokenizer, user, system=None):
    msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": user}]
    text = tokenizer.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
    return tokenizer.encode(text, add_special_tokens=False)


def generate_many(model, tokenizer, prompt_ids, max_tokens=768, temp=0.8, top_p=0.95, seed=0, batch_size=32):
    """Generate one completion per entry in prompt_ids (repeat entries to get several samples)."""
    mx.random.seed(seed)
    sampler = make_sampler(temp=temp, top_p=top_p if temp > 0 else 0.0)
    out = []
    for i in range(0, len(prompt_ids), batch_size):
        chunk = prompt_ids[i:i + batch_size]
        resp = batch_generate(model, tokenizer, prompts=chunk, max_tokens=max_tokens, sampler=sampler)
        out.extend(resp.texts)
    return out
