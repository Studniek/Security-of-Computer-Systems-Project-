import constants as CONSTS
import buttonFunctions as buttonF
import tkinter as tk

root = tk.Tk()

canvas = tk.Canvas(root, height=CONSTS.WINDOW_HEIGHT, width=CONSTS.WINDOW_WIDTH, bg=CONSTS.WINDOWS_BG_COLOR)
canvas.pack()

frame = tk.Frame(root, bg="white")
frame.place(relwidth=0.8, relheight=0.8, relx=0.1, rely=0.1)

crateChatButton = tk.Button(root, text="Create Chat", padx=10, pady=5, fg="white", bg=CONSTS.WINDOWS_BG_COLOR)
crateChatButton.pack()

sendMessageButton = tk.Button(root, text="Send Message", padx=10, pady=5, fg="white", bg=CONSTS.WINDOWS_BG_COLOR)
sendMessageButton.pack()

addFileButton = tk.Button(root, text="Add File", padx=10, pady=5,
                          fg="white", bg=CONSTS.WINDOWS_BG_COLOR,
                          command=buttonF.addFile)
addFileButton.pack()

root.mainloop()
