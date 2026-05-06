"""
Safe calculator tool — uses Python's AST parser instead of eval().

Only numeric literals and the following binary/unary operators are allowed:
  +  -  *  /  //  %  **  (unary + and -)

This eliminates the code-execution risk of the original eval()-based approach.
"""

import ast
import operator
from langchain.tools import tool

_BINARY_OPS: dict[type, callable] = {
    ast.Add:  operator.add,
    ast.Sub:  operator.sub,
    ast.Mult: operator.mul,
    ast.Div:  operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod:  operator.mod,
    ast.Pow:  operator.pow,
}

_UNARY_OPS: dict[type, callable] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}


def _safe_eval(node: ast.AST) -> float:
    """Recursively evaluate an AST expression using only allowed operations."""
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)

    if isinstance(node, ast.Constant):
        if isinstance(node.value, (int, float)):
            return float(node.value)
        raise ValueError(f"Only numeric constants are allowed, got: {type(node.value).__name__}")

    if isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _BINARY_OPS:
            raise ValueError(f"Operator not permitted: {op_type.__name__}")
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        if op_type is ast.Div and right == 0:
            raise ZeroDivisionError("Division by zero")
        if op_type is ast.FloorDiv and right == 0:
            raise ZeroDivisionError("Division by zero")
        return _BINARY_OPS[op_type](left, right)

    if isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _UNARY_OPS:
            raise ValueError(f"Unary operator not permitted: {op_type.__name__}")
        return _UNARY_OPS[op_type](_safe_eval(node.operand))

    raise ValueError(f"Unsupported expression type: {type(node).__name__}")


@tool
def calculator(expression: str) -> str:
    """Evaluate a mathematical expression safely.

    Input must contain only numbers and arithmetic operators: + - * / // % **
    Examples: '2 + 2', '10 * 5 / 2', '3 ** 4', '(100 - 20) / 4'
    Do NOT pass words or variable names — only numeric expressions.
    """
    try:
        tree = ast.parse(expression.strip(), mode="eval")
        result = _safe_eval(tree)
        # Format cleanly: drop trailing .0 for whole numbers
        if result == int(result):
            return str(int(result))
        return str(round(result, 10))
    except ZeroDivisionError:
        return "Error: Division by zero"
    except ValueError as exc:
        return f"Error: Invalid expression — {exc}"
    except SyntaxError:
        return "Error: Could not parse the expression. Please use only numbers and operators."
    except Exception as exc:
        return f"Calculation error: {exc}"
