from tkinter import filedialog, Text


def addFile():
    filenames = filedialog.askopenfilenames(initialdir="/", title="Select File")
