variable "base_dir" {
  type = string
}

variable "secret_content" {
  type      = string
  sensitive = true
}

resource "local_file" "counted" {
  count = 2

  filename = "${var.base_dir}/counted-${count.index}.txt"
  content  = "declared-count-${count.index}\n"
}

resource "local_file" "keyed" {
  for_each = toset(["blue", "green"])

  filename = "${var.base_dir}/keyed-${each.key}.txt"
  content  = "declared-key-${each.key}\n"
}

resource "local_sensitive_file" "secret" {
  filename = "${var.base_dir}/secret.txt"
  content  = var.secret_content
}
