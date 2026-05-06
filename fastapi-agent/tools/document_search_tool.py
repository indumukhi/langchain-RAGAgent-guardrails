"""
Document search tool backed by Pinecone + OpenAI Embeddings.

Extends the original with a thread-local context store so the guardrail
hallucination checker can inspect which documents were retrieved for a given
agent invocation without modifying the LangChain agent's public interface.
"""

import os
import threading
from langchain.tools import tool
from langchain_openai import OpenAIEmbeddings
from langchain_pinecone import PineconeVectorStore
from pinecone import Pinecone

# Thread-local storage: each request thread gets its own context list.
_local = threading.local()


def get_last_retrieved_docs() -> list[str]:
    """Return the raw text of documents retrieved in the current thread's last search."""
    return getattr(_local, "last_docs", [])


def _clear_retrieved_docs() -> None:
    _local.last_docs = []


def _build_retriever():
    pc = Pinecone(api_key=os.environ["PINECONE_API_KEY"])
    index = pc.Index(os.environ["PINECONE_INDEX_NAME"])
    embeddings = OpenAIEmbeddings(model="text-embedding-3-small")
    vectorstore = PineconeVectorStore(index=index, embedding=embeddings)
    return vectorstore.as_retriever(search_kwargs={"k": 4})


_retriever = None


def get_retriever():
    global _retriever
    if _retriever is None:
        _retriever = _build_retriever()
    return _retriever


@tool
def internal_document_search(query: str) -> str:
    """Search internal company documents for relevant information.

    Use this for questions about policies, procedures, products, or any
    company-specific topic.  Input should be a natural language query.
    """
    retriever = get_retriever()
    docs = retriever.invoke(query)

    if not docs:
        _local.last_docs = []
        return "No relevant documents found in the knowledge base."

    # Store raw text for hallucination checking by the output guardrail
    _local.last_docs = [doc.page_content for doc in docs]

    parts = [f"[Document {i + 1}]:\n{doc.page_content}" for i, doc in enumerate(docs)]
    return "\n\n---\n\n".join(parts)