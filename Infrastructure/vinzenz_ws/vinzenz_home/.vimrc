" vinzenz.fedora's .vimrc — sysadmin, minimal preferences

syntax on
set number
set ruler
set showcmd
set showmatch
set tabstop=4
set shiftwidth=4
set expandtab
set autoindent
set smartindent
set wrap
set linebreak
set incsearch
set hlsearch
set ignorecase
set smartcase
set background=dark
set scrolloff=3
set sidescrolloff=5
set wildmenu
set wildmode=longest:list,full
set backspace=indent,eol,start
set laststatus=2
set statusline=%F\ %m%r%h%w\ [%Y]\ [%l/%L,%c]\ %=%p%%

" Yaml + Ansible files — sane indent
autocmd FileType yaml,yml,ansible setlocal ts=2 sts=2 sw=2 expandtab

" Markdown for runbooks/notes — soft wrap, spell check
autocmd FileType markdown setlocal wrap linebreak nolist spell spelllang=en_us

" PostgreSQL .sql files — show trailing whitespace as it bites in COPY
autocmd FileType sql setlocal list listchars=trail:·,tab:»·

" Don't write swapfiles into the dir being edited (would noise up lab-fim)
set directory=~/.cache/vim/swap//
set backupdir=~/.cache/vim/backup//
set undodir=~/.cache/vim/undo//
set undofile

" Quick toggle for paste mode (used when pasting from chat into terminals)
set pastetoggle=<F2>
