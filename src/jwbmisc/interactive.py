def ask(question: str, default: None | str = None):
    if default is not None:
        question += f" [{default}]"
    answer = input(question.strip() + " ").strip()
    return answer if answer else default


def confirm(question: str, default: str = "n") -> bool:
    prompt = f"{question} (y/n)"
    answer = ask(prompt, default=default)
    if not answer:
        return False
    return answer.lower().startswith("y")
