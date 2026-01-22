#!/usr/bin/env python3
# python_basics.py
# The Python basics 

"""
Python Basics Demonstration (Interactive)
CVNP2646 - Week 2

This script demonstrates fundamental Python concepts
using user input in ALL sections.
"""

print("=" * 60)
print("PYTHON BASICS DEMONSTRATION (INTERACTIVE)")
print("=" * 60)
print()

# ========== SECTION 1: VARIABLES & DATA TYPES ==========
print("SECTION 1: Variables & Data Types")
print("-" * 60)

course_name = input("Enter course name: ")
student_count = int(input("Enter number of students: "))
pass_rate = float(input("Enter pass rate (%): "))
is_online = input("Is the course online? (yes/no): ").lower() == "yes"

languages_input = input("Enter programming languages (comma separated): ")
programming_languages = [lang.strip() for lang in languages_input.split(",")]

print("\n--- Stored Values ---")
print(f"String: {course_name}")
print(f"Integer: {student_count} students")
print(f"Float: {pass_rate}% pass rate")
print(f"Boolean: Course is online: {is_online}")
print(f"List: {programming_languages}")
print()

# ========== SECTION 2: CONDITIONAL STATEMENTS ==========
print("SECTION 2: Conditional Logic")
print("-" * 60)

if pass_rate >= 90:
    print("✅ Excellent pass rate!")
elif pass_rate >= 70:
    print("⚠️ Good pass rate")
else:
    print("❌ Needs improvement")

language_check = input("Enter a language to check: ")
if language_check in programming_languages:
    print(f"✅ {language_check} is in the list!")
else:
    print(f"❌ {language_check} is NOT in the list.")
print()

# ========== SECTION 3: LOOPS ==========
print("SECTION 3: Loops")
print("-" * 60)

print("Programming languages entered:")
for i, lang in enumerate(programming_languages, 1):
    print(f" {i}. {lang}")
print()

countdown = int(input("Enter a countdown start number: "))
print("Countdown:")
while countdown > 0:
    print(f" {countdown}...")
    countdown -= 1
print(" 🚀 Countdown complete!")
print()

# ========== SECTION 4: STRING MANIPULATION ==========
print("SECTION 4: String Manipulation")
print("-" * 60)

sample_text = input("Enter a sample string: ")

print(f"Original: '{sample_text}'")
print(f"Stripped: '{sample_text.strip()}'")
print(f"Uppercase: '{sample_text.upper()}'")
print(f"Lowercase: '{sample_text.lower()}'")

old_word = input("Enter a word to replace: ")
new_word = input("Enter replacement word: ")
print(f"Replaced: '{sample_text.replace(old_word, new_word)}'")
print()

# ========== SECTION 5: BASIC MATH OPERATIONS ==========
print("SECTION 5: Math Operations")
print("-" * 60)

num1 = float(input("Enter first number: "))
num2 = float(input("Enter second number: "))

print(f"Addition: {num1} + {num2} = {num1 + num2}")
print(f"Subtraction: {num1} - {num2} = {num1 - num2}")
print(f"Multiplication: {num1} * {num2} = {num1 * num2}")

if num2 != 0:
    print(f"Division: {num1} / {num2} = {num1 / num2}")
    print(f"Floor Division: {num1} // {num2} = {num1 // num2}")
    print(f"Modulus: {num1} % {num2} = {num1 % num2}")
else:
    print("❌ Division by zero is not allowed.")

print(f"Exponent: {num1} ** {num2} = {num1 ** num2}")
print()

# ========== CONCLUSION ==========
print("=" * 60)
print("✅ Python Basics Demonstration Complete!")
print("=" * 60)

