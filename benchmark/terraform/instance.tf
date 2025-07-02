data "openstack_networking_network_v2" "private_network" {
  name = "private"
}

# Instance 1
resource "openstack_compute_instance_v2" "benchie_1" {
  name        = "Benchie-1"
  flavor_id   = "3"
  key_pair    = var.SSH_KEYPAIR
  image_id    = data.openstack_images_image_v2.debian12.id

  network {
    port = openstack_networking_port_v2.benchie_1_port.id
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
    port = openstack_networking_port_v2.benchie_2_port.id
  }

  lifecycle {
    ignore_changes = [key_pair]
  }
}

# Network ports for instances
resource "openstack_networking_port_v2" "benchie_1_port" {
  name       = "benchie-1-port"
  network_id = data.openstack_networking_network_v2.private_network.id
}

resource "openstack_networking_port_v2" "benchie_2_port" {
  name       = "benchie-2-port"
  network_id = data.openstack_networking_network_v2.private_network.id
}

# Floating IPs for instances
resource "openstack_networking_floatingip_v2" "benchie_1_floating_ip" {
  pool = "public"
}

resource "openstack_networking_floatingip_v2" "benchie_2_floating_ip" {
  pool = "public"
}

# Floating IP associations using networking association
resource "openstack_networking_floatingip_associate_v2" "benchie_1_fip_assoc" {
  floating_ip = "${openstack_networking_floatingip_v2.benchie_1_floating_ip.address}"
  port_id     = "${openstack_networking_port_v2.benchie_1_port.id}"
}

resource "openstack_networking_floatingip_associate_v2" "benchie_2_fip_assoc" {
  floating_ip = "${openstack_networking_floatingip_v2.benchie_2_floating_ip.address}"
  port_id     = "${openstack_networking_port_v2.benchie_2_port.id}"
}

# Outputs
output "benchie_1_floating_ip" {
  value = openstack_networking_floatingip_v2.benchie_1_floating_ip.address
}

output "benchie_2_floating_ip" {
  value = openstack_networking_floatingip_v2.benchie_2_floating_ip.address
}

