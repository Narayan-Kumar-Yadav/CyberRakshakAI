from __future__ import annotations

from aiogram.types import KeyboardButton, ReplyKeyboardMarkup


def main_keyboard() -> ReplyKeyboardMarkup:
    return ReplyKeyboardMarkup(
        keyboard=[
            [KeyboardButton(text="/breach email@example.com"), KeyboardButton(text="/analyze suspicious text")],
            [KeyboardButton(text="/username @telegram"), KeyboardButton(text="/ask security question")],
            [KeyboardButton(text="/history"), KeyboardButton(text="/help")],
        ],
        resize_keyboard=True,
        input_field_placeholder="Choose a cybersecurity action",
    )
