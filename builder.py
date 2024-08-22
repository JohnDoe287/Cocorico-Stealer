import curses
import subprocess

def build_executable(options):
    config_content = f"""
CHAT_ID = '{options['chat_id']}'
TOKEN = '{options['token']}'
    """
    
    with open('config.py', 'w') as config_file:
        config_file.write(config_content.strip())

    command = 'pyinstaller --onefile main.py'

    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print("Python executable built successfully!")
        print(result.stdout)
    except subprocess.CalledProcessError as e:
        print(f"An error occurred: {e.stderr}")
        print(e.stderr)

def main(stdscr):
    curses.curs_set(1)
    curses.echo()
    stdscr.clear()
    stdscr.refresh()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
    saved = [False, False]

    options = {
        'chat_id': '',
        'token': '',
    }

    menu = [
        'Enter Chat ID',
        'Enter Token',
        'Reset',
        'Build Executable'
    ]

    current_row = 0
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        for idx, item in enumerate(menu):
            x = w // 2 - len(item) // 2
            y = h // 2 - len(menu) // 2 + idx
            if idx == current_row:
                stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(y, x, item)
                stdscr.attroff(curses.A_REVERSE)
            else:
                stdscr.addstr(y, x, item)
        
        chat_id_display = 'Chat ID: ' + (options['chat_id'] if saved[0] else '')
        token_display = 'Token: ' + (options['token'] if saved[1] else '')

        stdscr.addstr(h // 2 + len(menu) // 2 + 1, w // 2 - len(chat_id_display) // 2, chat_id_display, curses.color_pair(1 if saved[0] else 2))
        stdscr.addstr(h // 2 + len(menu) // 2 + 2, w // 2 - len(token_display) // 2, token_display, curses.color_pair(1 if saved[1] else 2))

        stdscr.refresh()
        key = stdscr.getch()

        if key == curses.KEY_DOWN and current_row < len(menu) - 1:
            current_row += 1
        elif key == curses.KEY_UP and current_row > 0:
            current_row -= 1
        elif key == ord('\n'):
            if current_row == len(menu) - 1:
                build_executable(options)
                break
            elif current_row == 0:
                stdscr.addstr(h // 2 + len(menu) // 2 + 3, w // 2 - len('Enter Chat ID:') // 2, 'Enter Chat ID: ')
                stdscr.refresh()
                options['chat_id'] = stdscr.getstr().decode('utf-8')
                saved[0] = True
            elif current_row == 1:
                stdscr.addstr(h // 2 + len(menu) // 2 + 4, w // 2 - len('Enter Token:') // 2, 'Enter Token: ')
                stdscr.refresh()
                options['token'] = stdscr.getstr().decode('utf-8')
                saved[1] = True
            elif current_row == 2:
                saved = [False, False]
            elif current_row == 3:
                build_executable(options)
                break

    curses.noecho()
curses.wrapper(main)
