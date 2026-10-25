
# ===== CELL 3: Registry + Engine (paste engine.py code) =====
# engine.py - LLM Engine
"""
LLM Engine for Multi-Agent System
"""
import os
import time
import openai
from openai import OpenAI
from abc import abstractmethod


class Registry:
    """Global registry for classes"""
    def __init__(self):
        self._registry = {}

    def register(self, alias, class_reference):
        self._registry[alias] = class_reference

    def get_class(self, alias):
        return self._registry.get(alias)


registry = Registry()


def register_class(alias=None):
    """Decorator to register classes"""
    def decorator(cls):
        nonlocal alias
        if alias is None:
            alias = cls.__name__
        registry.register(alias, cls)
        return cls
    return decorator


@register_class(alias="Engine.Base")
class Engine:
    """Base engine class"""
    def __init__(self):
        pass

    @staticmethod
    def add_parser_args(parser):
        pass

    @abstractmethod
    def get_response(self, messages):
        pass


@register_class(alias="Engine.GPT")
class GPTEngine(Engine):
    """OpenAI GPT Engine"""
    def __init__(self, openai_api_key, openai_api_base=None, openai_model_name=None,
                 temperature=0.0, max_completion_tokens=2048, top_p=1, frequency_penalty=0, presence_penalty=0):

        openai_api_key = openai_api_key if openai_api_key is not None else os.environ.get('OPENAI_API_KEY')
        assert openai_api_key is not None, "OPENAI_API_KEY is required"
        openai_api_base = openai_api_base if openai_api_base is not None else os.environ.get('OPENAI_API_BASE')

        self.model_name = openai_model_name or "gpt-4"
        self.temperature = temperature
        self.max_completion_tokens = max_completion_tokens
        self.top_p = top_p
        self.frequency_penalty = frequency_penalty
        self.presence_penalty = presence_penalty

        if openai_api_base:
            self.client = OpenAI(api_key=openai_api_key, base_url=openai_api_base)
        else:
            self.client = OpenAI(api_key=openai_api_key)

    def get_response(self, messages):
        """Get response from OpenAI"""
        model_name = self.model_name
        last_err = None

        for attempt in range(5):
            try:
                resp = self.client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    temperature=self.temperature,
                    max_completion_tokens=self.max_completion_tokens,
                    top_p=self.top_p,
                    frequency_penalty=self.frequency_penalty,
                    presence_penalty=self.presence_penalty
                )
                return resp.choices[0].message.content

            except openai.BadRequestError as e:
                last_err = e
                print(f"⚠️ BadRequestError (attempt {attempt+1}/5): {e}")
                time.sleep(1)

            except openai.RateLimitError as e:
                last_err = e
                print(f"⚠️ RateLimitError (attempt {attempt+1}/5): {e}")
                time.sleep(10)

            except Exception as e:
                last_err = e
                print(f"⚠️ Error (attempt {attempt+1}/5): {e}")
                time.sleep(5)

        raise RuntimeError(f"OpenAI request failed after 5 retries: {last_err}")
