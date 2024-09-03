# TESTING

from win10toast import ToastNotifier

def create_notification(title, message):
    toaster = ToastNotifier()
    toaster.show_toast(title, message, duration=10)

if __name__ == "__main__":
    title = input("enter title : ")
    message = input("enter message : ")
    create_notification(title, message)