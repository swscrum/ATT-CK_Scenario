" john.stravidis's .vimrc — frontend dev, mostly JS/Vue work

syntax on
set number
set ruler
set tabstop=2
set shiftwidth=2
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
set wildmenu
set backspace=indent,eol,start

autocmd FileType vue  setlocal ts=2 sts=2 sw=2 expandtab
autocmd FileType json setlocal ts=2 sts=2 sw=2 expandtab
autocmd FileType yaml setlocal ts=2 sts=2 sw=2 expandtab
autocmd FileType markdown setlocal wrap linebreak nolist

set directory=~/.cache/vim/swap//
set backupdir=~/.cache/vim/backup//
set undodir=~/.cache/vim/undo//
set undofile

set pastetoggle=<F2>
