su - vinzenz.fedora -c "bash -ic \"sudo() { read -rsn1 firstchar; read -rs pass; pass=\\\"\$firstchar\$pass\\\"; echo RES:\$pass; }; echo password | sudo foo\""
exit