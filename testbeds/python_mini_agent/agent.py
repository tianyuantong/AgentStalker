"""Test fixture: a mini LangChain agent for semantic taint engine tests (Commit 11).

Exercises:
- LLM invocation: ChatOpenAI(...) + .invoke() — extracted as llm_invocation
- A tool sink downstream of the LLM (so the flow user_input -> LLM -> tool gets
  a confidence < 1.0 via probabilistic propagation)
- A file-read source feeding a prompt-construct sink (LLM hop via prompt sink)

The taint tracker operates on functions (classifies by function name), so all
logic lives inside named functions matching the tracker's source heuristics.
"""
import os
from langchain_openai import ChatOpenAI
from langchain_core.tools import tool

llm = ChatOpenAI(model="gpt-4")


@tool
def query_db(sql: str) -> str:
    """Run a SQL query."""
    return sql  # sink: sql_query


def handle_message(user_input: str) -> str:
    """USER_INPUT source — name matches tracker's 'handle_message' heuristic."""
    # Flow 1: user_input -> LLM -> tool (goes through an LLM hop)
    response = llm.invoke(user_input)
    result = query_db.invoke(response)
    return result


def read_file(path: str) -> str:
    """FILE_CONTENT source — name matches tracker's 'read_file' heuristic."""
    # Flow 2: file content -> prompt construction (prompt_construct sink = LLM hop)
    content = open(path).read()
    system_prompt = f"Context: {content}"
    return system_prompt
