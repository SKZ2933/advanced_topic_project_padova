package com.example;

import net.fabricmc.api.ClientModInitializer;
import net.fabricmc.fabric.api.client.event.lifecycle.v1.ClientTickEvents;
import net.minecraft.world.entity.LivingEntity;

public class ExampleModClient implements ClientModInitializer {
	@Override
	public void onInitializeClient() {
		// C'est ici qu'on branche le moteur : on écoute chaque tick du jeu
		ClientTickEvents.END_CLIENT_TICK.register(client -> {
			if (client.player != null && client.level != null) {

				// 1. Trouver l'entité vivante la plus proche (Zombie, Animal, etc.)
				LivingEntity target = client.level.getEntitiesOfClass(LivingEntity.class,
								client.player.getBoundingBox().inflate(20.0), // Rayon de 20 blocs
								e -> e != client.player && e.isAlive())
						.stream()
						.min((e1, e2) -> Float.compare(e1.distanceTo(client.player), e2.distanceTo(client.player)))
						.orElse(null);

				if (target != null) {
					// 2. Appeler ton algorithme dans AimLogic
					float[] rotations = AimLogic.getRotations(client.player, target);

					// 3. Forcer la caméra vers la cible
					client.player.setYRot(rotations[0]);
					client.player.setXRot(rotations[1]);
				}
			}
		});
	}
}