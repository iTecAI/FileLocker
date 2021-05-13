from context_menu import menus
import filelocker

menus.removeMenu('FileLocker - Encrypt', type='FILES')
menus.FastCommand('FileLocker - Encrypt', type='FILES', python=filelocker.encrypt_file).compile()
menus.removeMenu('FileLocker - Decrypt', type='.filelock')
menus.FastCommand('FileLocker - Decrypt', type='.filelock', python=filelocker.decrypt_file).compile()
menus.removeMenu('FileLocker - Encrypt', type='DIRECTORY')
menus.FastCommand('FileLocker - Encrypt', type='DIRECTORY', python=filelocker.encrypt_folder).compile()
menus.removeMenu('FileLocker - Decrypt', type='.dirlock')
menus.FastCommand('FileLocker - Decrypt', type='.dirlock', python=filelocker.decrypt_folder).compile()