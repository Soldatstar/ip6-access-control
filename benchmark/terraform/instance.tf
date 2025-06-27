
# Simple compute instances configuration for benchmarking
# Two identical instances with floating IPs

# Instance 1
resource "openstack_compute_instance_v2" "benchie_1" {
  name        = "Benchie-1"
  flavor_id   = "3"
  key_pair    = var.SSH_KEYPAIR
  image_id    = data.openstack_images_image_v2.debian12.id

  network {
    name = "private"
  }

  lifecycle {
    ignore_changes = [key_pair]
  }
}

# Instance 2
resource "openstack_compute_instance_v2" "benchie_2" {
  name        = "Benchie-2"
  flavor_id   = "3"
  key_pair    = var.SSH_KEYPAIR
  image_id    = data.openstack_images_image_v2.debian12.id

  network {
    name = "private"
  }

  lifecycle {
    ignore_changes = [key_pair]
  }
}

# Floating IPs for instances
resource "openstack_networking_floatingip_v2" "benchie_1_floating_ip" {
  pool = "public"
}

resource "openstack_networking_floatingip_v2" "benchie_2_floating_ip" {
  pool = "public"
}

# Floating IP associations
resource "openstack_compute_floatingip_associate_v2" "benchie_1_fip_assoc" {
  floating_ip = openstack_networking_floatingip_v2.benchie_1_floating_ip.address
  instance_id = openstack_compute_instance_v2.benchie_1.id
}

resource "openstack_compute_floatingip_associate_v2" "benchie_2_fip_assoc" {
  floating_ip = openstack_networking_floatingip_v2.benchie_2_floating_ip.address
  instance_id = openstack_compute_instance_v2.benchie_2.id
}

# Outputs
output "benchie_1_floating_ip" {
  value = openstack_networking_floatingip_v2.benchie_1_floating_ip.address
}

output "benchie_2_floating_ip" {
  value = openstack_networking_floatingip_v2.benchie_2_floating_ip.address
}
