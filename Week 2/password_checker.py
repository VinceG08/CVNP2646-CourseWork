#!/usr/bin/env python3
# password_check.py
# Checks passwords

def check_password_strength(password):
    """
    Evaluates password strength based on multiple criteria.

    Args:
        password (str): The password to evaluate

    Returns:
        str: Strength rating with feedback
    """
    score = 0
    feedback = []

    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Too short (minimum 8 characters)")

    # Check for uppercase letters
    if any(c.isupper() for c in password):
        score += 1
    else:
        feedback.append("Add uppercase letters")

    # Check for lowercase letters
    if any(c.islower() for c in password):
        score += 1
    else:
        feedback.append("Add lowercase letters")

    # Check for digits
    if any(c.isdigit() for c in password):
        score += 1
    else:
        feedback.append("Add numbers")

    # Check for special characters
    special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    if any(c in special_chars for c in password):
        score += 1
    else:
        feedback.append("Add special characters")

    # Determine strength rating
    if score <= 2:
        rating = "WEAK ❌"
    elif score <= 4:
        rating = "MEDIUM ⚠️"
    else:
        rating = "STRONG ✅"

    # Build result message
    if feedback:
        return f"{rating} - Issues: {', '.join(feedback)}"
    else:
        return f"{rating} - Excellent password!"


# Real-time user input loop
print("Password Strength Checker")
print("=" * 60)
print("Type 'exit' to quit.\n")

while True:
    user_password = input("Enter a password: ")

    if user_password.lower() == "exit":
        print("\nExiting Password Strength Checker. Goodbye! 👋")
        break

    result = check_password_strength(user_password)
    print(result)
    print()

