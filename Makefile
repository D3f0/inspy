all:
	$(MAKE) -C docker
	poetry build
